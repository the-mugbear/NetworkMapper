"""Ingestion pipeline for handling large scan uploads.

The ingestion service streams uploads to disk, tracks job metadata,
and processes each file in a background worker so API requests stay fast.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Type
from uuid import uuid4

from fastapi import UploadFile
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Host, HostScanHistory, IngestionJob
from app.db.session import SessionLocal
from app.services.dns_service import DNSService
from app.services.parse_error_service import log_parse_error

logger = logging.getLogger(__name__)


ParserDescriptor = Tuple[str, Type, str]


class ParseFailure(RuntimeError):
    """Exception raised when an ingestion job fails due to parsing issues."""

    def __init__(
        self,
        message: str,
        *,
        user_message: Optional[str] = None,
        error_id: Optional[int] = None,
        underlying_error: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.user_message = user_message
        self.error_id = error_id
        self.underlying_error = underlying_error


class IngestionService:
    """Coordinate file storage, job tracking, and background parsing."""

    def __init__(self) -> None:
        self._storage_root = Path(settings.INGESTION_STORAGE_DIR)
        try:
            self._storage_root.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            fallback = Path("/tmp/networkmapper_ingestion") / uuid4().hex
            fallback.mkdir(parents=True, exist_ok=True)
            logger.warning(
                "Ingestion storage %s not writable, falling back to %s",
                self._storage_root,
                fallback,
            )
            self._storage_root = fallback
        self._executor = ThreadPoolExecutor(max_workers=settings.INGESTION_WORKERS)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        """Ensure ingestion_jobs schema supports parse-error linkage."""

        # Add the nullable column first; commit immediately so the column persists even if
        # follow-on DDL (like the FK) fails due to missing dependency tables.
        try:
            with SessionLocal() as db:
                db.execute(
                    text(
                        "ALTER TABLE ingestion_jobs ADD COLUMN IF NOT EXISTS parse_error_id INTEGER"
                    )
                )
                db.commit()
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Unable to add parse_error_id column to ingestion_jobs: %s", exc)

        # Attempt to wire up the foreign-key constraint if the parse_errors table exists.
        try:
            with SessionLocal() as db:
                dialect = db.bind.dialect.name if db.bind else ""
                if dialect == "postgresql":
                    table_exists = db.execute(
                        text("SELECT to_regclass('parse_errors') IS NOT NULL")
                    ).scalar()
                elif dialect == "sqlite":
                    table_exists = db.execute(
                        text(
                            "SELECT 1 FROM sqlite_master "
                            "WHERE type = 'table' AND name = 'parse_errors'"
                        )
                    ).scalar()
                else:
                    table_exists = db.execute(
                        text(
                            "SELECT 1 FROM information_schema.tables "
                            "WHERE table_name = 'parse_errors'"
                        )
                    ).scalar()

                if table_exists:
                    db.execute(
                        text(
                            "ALTER TABLE ingestion_jobs "
                            "ADD CONSTRAINT IF NOT EXISTS ingestion_jobs_parse_error_id_fkey "
                            "FOREIGN KEY (parse_error_id) REFERENCES parse_errors(id)"
                        )
                    )
                    db.commit()
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Unable to add ingestion_jobs parse_error_id FK: %s", exc)

    async def create_job(
        self,
        db: Session,
        upload: UploadFile,
        submitted_by_id: Optional[int],
        options: Optional[Dict[str, object]] = None,
    ) -> IngestionJob:
        """Persist an upload to disk and register an ingestion job."""
        job_token = uuid4().hex
        job_dir = self._storage_root / job_token
        job_dir.mkdir(parents=True, exist_ok=True)

        destination = job_dir / upload.filename
        file_size = await self._write_upload(upload, destination)

        job = IngestionJob(
            filename=destination.name,
            original_filename=upload.filename,
            storage_path=str(destination),
            status="queued",
            file_size=file_size,
            options=options or {},
            submitted_by_id=submitted_by_id,
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        logger.info("Queued ingestion job %s for %s (%d bytes)", job.id, upload.filename, file_size)
        return job

    def enqueue_job(self, job_id: int) -> None:
        """Schedule a job for background processing."""
        self._executor.submit(self._run_job, job_id)

    async def _write_upload(self, upload: UploadFile, destination: Path) -> int:
        """Stream an upload to disk in chunks, returning written size."""
        chunk_size = settings.UPLOAD_CHUNK_SIZE
        total_written = 0

        await upload.seek(0)
        with destination.open("wb") as outfile:
            while True:
                chunk = await upload.read(chunk_size)
                if not chunk:
                    break
                outfile.write(chunk)
                total_written += len(chunk)
                if total_written > settings.MAX_FILE_SIZE:
                    destination.unlink(missing_ok=True)
                    raise ValueError(
                        "File too large. Increase MAX_FILE_SIZE or provide a smaller upload."
                    )

        await upload.close()
        return total_written

    # ------------------------------------------------------------------
    # Background worker

    def _run_job(self, job_id: int) -> None:
        db = SessionLocal()
        try:
            job = db.query(IngestionJob).filter(IngestionJob.id == job_id).first()
            if not job:
                logger.error("Ingestion job %s not found", job_id)
                return

            job.status = "processing"
            job.started_at = datetime.utcnow()
            job.message = "Processing queued file"
            db.commit()

            result = self._process_job(db, job)
            job = db.get(IngestionJob, job_id)  # Refresh job state
            if result:
                job.status = "completed"
                job.completed_at = datetime.utcnow()
                job.scan_id = result.get("scan_id")
                job.tool_name = result.get("tool_name")
                job.message = result.get("message")
                job.parse_error_id = None
                db.commit()
        except ParseFailure as exc:
            db.rollback()
            job = db.get(IngestionJob, job_id)
            if job:
                job.status = "failed"
                job.error_message = exc.user_message or exc.underlying_error or str(exc)
                job.message = job.error_message
                if exc.error_id:
                    job.message = f"{job.message} (Error ID: {exc.error_id})"
                job.parse_error_id = exc.error_id
                job.completed_at = datetime.utcnow()
                db.commit()
            logger.warning(
                "Failed ingestion job %s due to parse error: %s",
                job_id,
                exc.user_message or exc.underlying_error or str(exc),
            )
        except Exception as exc:  # pragma: no cover - defensive logging
            db.rollback()
            job = db.get(IngestionJob, job_id)
            if job:
                job.status = "failed"
                job.error_message = str(exc)
                job.completed_at = datetime.utcnow()
                job.parse_error_id = None
                db.commit()
            logger.exception("Failed ingestion job %s", job_id)
        finally:
            db.close()

    def _process_job(self, db: Session, job: IngestionJob) -> Optional[Dict[str, object]]:
        """Run parser detection and execute the first successful parser."""
        storage_path = Path(job.storage_path)
        if not storage_path.exists():
            raise FileNotFoundError(f"Uploaded file missing at {storage_path}")

        sample = self._read_sample(storage_path)
        parsing_attempts = list(self._build_parsing_attempts(job, sample))
        if not parsing_attempts:
            preview = sample[:4096]
            parse_error = log_parse_error(
                db=db,
                filename=job.original_filename,
                file_content=preview,
                error_type="format_error",
                file_type="unknown",
                custom_message="Unsupported file type or format."
            )
            raise ParseFailure(
                "Unsupported file type or format",
                user_message=parse_error.user_message,
                error_id=parse_error.id,
            )

        last_error: Optional[Exception] = None
        for file_type, parser_class, description in parsing_attempts:
            start = time.time()
            try:
                logger.info(
                    "Job %s: attempting parser %s for %s",
                    job.id,
                    parser_class.__name__,
                    job.original_filename,
                )
                result = self._execute_parser(db, job, parser_class, description)
                elapsed = time.time() - start
                logger.info(
                    "Job %s: parser %s succeeded in %.2fs",
                    job.id,
                    parser_class.__name__,
                    elapsed,
                )
                return result
            except Exception as exc:
                db.rollback()
                elapsed = time.time() - start
                logger.warning(
                    "Job %s: parser %s failed after %.2fs: %s",
                    job.id,
                    parser_class.__name__,
                    elapsed,
                    exc,
                )
                last_error = exc
                continue

        preview = sample[:4096]
        parse_error = log_parse_error(
            db=db,
            filename=job.original_filename,
            file_content=preview,
            error=last_error,
            error_type="parsing_error",
            file_type=parsing_attempts[0][0] if parsing_attempts else "unknown",
        )
        raise ParseFailure(
            "Failed to parse file",
            user_message=parse_error.user_message,
            error_id=parse_error.id,
            underlying_error=str(last_error) if last_error else None,
        )

    def _execute_parser(
        self,
        db: Session,
        job: IngestionJob,
        parser_class: Type,
        description: str,
    ) -> Dict[str, object]:
        from app.parsers.nmap_parser import NmapXMLParser
        from app.parsers.eyewitness_parser import EyewitnessParser
        from app.parsers.masscan_parser import MasscanParser
        from app.parsers.dns_parser import DNSParser
        from app.parsers.netexec_parser import NetexecParser
        from app.services.nessus_integration_service import NessusIntegrationService

        options = job.options or {}
        storage_path = job.storage_path
        filename = job.original_filename

        if parser_class is NessusIntegrationService:
            parser_instance = NessusIntegrationService(db)
            result = parser_instance.process_nessus_file(storage_path, filename)
            if not result.get("success"):
                raise ParseFailure(
                    "Nessus processing failed",
                    user_message=result.get("message") or result.get("error"),
                    underlying_error=result.get("error"),
                )
            db.commit()
            scan_id = result.get("scan_id")
            message = result.get("message")
            tool_name = "Nessus"
        else:
            # Map class references back to callable constructors
            parser_map = {
                NmapXMLParser: NmapXMLParser,
                EyewitnessParser: EyewitnessParser,
                MasscanParser: MasscanParser,
                DNSParser: DNSParser,
                NetexecParser: NetexecParser,
            }
            parser_ctor = parser_map.get(parser_class)
            if parser_ctor is None:
                raise ValueError(f"Unsupported parser class {parser_class}")

            parser = parser_ctor(db)
            scan = parser.parse_file(storage_path, filename)
            db.commit()
            scan_id = getattr(scan, "id", None)
            tool_name = getattr(scan, "tool_name", parser_class.__name__)
            message = f"{description} processed successfully"

        if options.get("enrich_dns") and scan_id:
            dns_server = options.get("dns_server")
            enriched = self._enrich_dns(db, scan_id, dns_server)
            if enriched:
                db.commit()
                message = f"{message} (DNS enriched {enriched} hosts)"

        return {
            "scan_id": scan_id,
            "message": message,
            "tool_name": tool_name,
        }

    def _enrich_dns(self, db: Session, scan_id: int, dns_server: Optional[str]) -> int:
        dns_service = DNSService(db, custom_dns_server=dns_server if dns_server else None)
        hosts = (
            db.query(Host)
            .join(HostScanHistory, Host.id == HostScanHistory.host_id)
            .filter(HostScanHistory.scan_id == scan_id)
            .all()
        )

        enriched_count = 0
        for host in hosts:
            try:
                enrichment = dns_service.enrich_host_data(host)
                if enrichment.get("reverse_dns") or enrichment.get("dns_records"):
                    enriched_count += 1
            except Exception as exc:  # pragma: no cover - log and continue
                logger.warning(
                    "DNS enrichment failed for host %s: %s",
                    host.ip_address,
                    exc,
                )
        return enriched_count

    # ------------------------------------------------------------------
    # Parser detection helpers

    def _build_parsing_attempts(
        self, job: IngestionJob, sample: bytes
    ) -> Iterable[ParserDescriptor]:
        from app.parsers.nmap_parser import NmapXMLParser
        from app.parsers.eyewitness_parser import EyewitnessParser
        from app.parsers.masscan_parser import MasscanParser
        from app.parsers.dns_parser import DNSParser
        from app.parsers.netexec_parser import NetexecParser
        from app.services.nessus_integration_service import NessusIntegrationService

        filename = job.original_filename.lower()
        attempts: List[ParserDescriptor] = []

        if filename.endswith(".nessus") or (
            filename.endswith(".xml") and self._is_nessus_sample(sample)
        ):
            attempts.append(("nessus_xml", NessusIntegrationService, "Nessus vulnerability scan"))

        if filename.endswith(".xml"):
            attempts.append(("nmap_xml", NmapXMLParser, "Nmap XML file"))
            attempts.append(("masscan_xml", MasscanParser, "Masscan XML file"))
            attempts.append(("nessus_xml", NessusIntegrationService, "Nessus vulnerability scan"))
        elif filename.endswith(".gnmap"):
            try:
                from app.parsers.gnmap_parser import GnmapParser

                attempts.append(("nmap_gnmap", GnmapParser, "Nmap .gnmap file"))
            except ImportError as exc:
                logger.warning("Gnmap parser unavailable: %s", exc)
        elif filename.endswith(".json"):
            if self._looks_like_netexec(sample, filename):
                from app.parsers.netexec_parser import NetexecParser as NetexecJsonParser

                attempts.append(("netexec_json", NetexecJsonParser, "NetExec JSON output"))
            if "masscan" in filename:
                attempts.append(("masscan_json", MasscanParser, "Masscan JSON file"))
            if "eyewitness" in filename or "report" in filename:
                attempts.append(("eyewitness_json", EyewitnessParser, "Eyewitness report"))
        elif filename.endswith(".csv"):
            if "eyewitness" in filename or "report" in filename:
                attempts.append(("eyewitness_csv", EyewitnessParser, "Eyewitness report"))
            attempts.append(("dns_csv", DNSParser, "DNS records CSV file"))
        elif filename.endswith(".txt"):
            if self._looks_like_netexec(sample, filename):
                attempts.append(("netexec_output", NetexecParser, "NetExec output file"))
            else:
                attempts.append(("masscan_list", MasscanParser, "Masscan output file"))

        return attempts

    def _read_sample(self, path: Path, size: int = 64 * 1024) -> bytes:
        with path.open("rb") as handle:
            return handle.read(size)

    def _is_nessus_sample(self, sample: bytes) -> bool:
        text = sample.decode("utf-8", errors="ignore").lower()
        indicators = [
            "nessusclientdata_v2",
            "<reporthost",
            "pluginid",
            "tenable",
            "reportitem",
        ]
        return sum(1 for token in indicators if token in text) >= 3

    def _looks_like_netexec(self, sample: bytes, filename: str) -> bool:
        lowered = sample.decode("utf-8", errors="ignore").lower()
        name = filename.lower()
        indicators = [
            "netexec",
            "nxc",
            "spider",
            "smb         ",
            "ldap        ",
            "winrm       ",
        ]
        if any(token in lowered for token in indicators):
            return True
        return "netexec" in name or "nxc" in name


ingestion_service = IngestionService()

__all__ = ["ingestion_service", "IngestionService"]
