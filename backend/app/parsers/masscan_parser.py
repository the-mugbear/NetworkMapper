"""Masscan parser with streaming ingestion and deduplicated persistence."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from lxml import etree
from sqlalchemy.orm import Session

from app.db import models
from app.services.host_deduplication_service import HostDeduplicationService
from app.services.subnet_correlation import SubnetCorrelationService

logger = logging.getLogger(__name__)


class MasscanParser:
    """Parse Masscan output formats while preserving low memory usage."""

    OUT_OF_SCOPE_BATCH_SIZE = 250

    def __init__(self, db: Session):
        self.db = db
        self.dedup_service = HostDeduplicationService(db)
        self.correlation_service = SubnetCorrelationService(db)

    def parse_file(self, file_path: str, filename: str) -> models.Scan:
        """Dispatch to format-specific parsers based on file extension."""
        scan = self._create_scan_record(filename)
        pending_out_of_scope: Dict[str, Dict[str, Any]] = {}
        processed_hosts = 0

        try:
            suffix = Path(filename).suffix.lower()
            if suffix == ".xml":
                processed_hosts = self._parse_xml(file_path, scan, pending_out_of_scope)
            elif suffix == ".json":
                processed_hosts = self._parse_json(file_path, scan, pending_out_of_scope)
            else:
                processed_hosts = self._parse_list(file_path, scan, pending_out_of_scope)

            self._flush_out_of_scope(scan.id, pending_out_of_scope)
            self.db.flush()

            try:
                correlated = self.correlation_service.batch_correlate_scan_hosts_to_subnets(scan.id)
                logger.info(
                    "Masscan scan %s correlated %s hosts to subnets", scan.id, correlated
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Masscan scan %s correlation failed: %s", scan.id, exc)

            self.db.commit()
            logger.info(
                "Masscan parser processed %s hosts (filename=%s)", processed_hosts, filename
            )
            return scan
        except Exception:
            self.db.rollback()
            logger.exception("Masscan parser failed for %s", filename)
            raise

    # ------------------------------------------------------------------
    # Format-specific parsers

    def _parse_xml(
        self,
        file_path: str,
        scan: models.Scan,
        pending_out_of_scope: Dict[str, Dict[str, Any]],
    ) -> int:
        processed_hosts = 0
        context = etree.iterparse(file_path, events=("start", "end"))

        for event, elem in context:
            tag = self._strip_namespace(elem.tag)

            if event == "start" and tag in {"nmaprun", "masscan"}:
                scan.version = elem.get("version")
                scan.command_line = elem.get("args")
                scan.tool_name = elem.get("scanner", "masscan")
                scan.start_time = self._parse_timestamp(elem.get("start"))

            if event == "end" and tag == "host":
                host_info = self._extract_xml_host(elem)
                if host_info:
                    if self._handle_host(scan.id, host_info["ip_address"], host_info["ports"], pending_out_of_scope):
                        processed_hosts += 1
                self._clear_element(elem)

        return processed_hosts

    def _parse_json(
        self,
        file_path: str,
        scan: models.Scan,
        pending_out_of_scope: Dict[str, Dict[str, Any]],
    ) -> int:
        processed_hosts = 0
        for entry in self._iter_json_entries(file_path):
            ip_address = entry.get("ip") or entry.get("addr")
            if not ip_address:
                continue

            ports = []
            for port_info in entry.get("ports", []):
                try:
                    port_number = int(port_info.get("port"))
                except (TypeError, ValueError):
                    continue
                protocol = port_info.get("proto", "tcp")
                state = port_info.get("status", "open")
                if state != "open":
                    continue
                ports.append(
                    {
                        "port_number": port_number,
                        "protocol": protocol,
                        "state": state,
                    }
                )

            if ports and self._handle_host(scan.id, ip_address, ports, pending_out_of_scope):
                processed_hosts += 1

        return processed_hosts

    def _parse_list(
        self,
        file_path: str,
        scan: models.Scan,
        pending_out_of_scope: Dict[str, Dict[str, Any]],
    ) -> int:
        processed_hosts = 0
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split()
                if len(parts) < 4:
                    continue

                state, protocol, port_str, ip_address = parts[:4]
                if state != "open":
                    continue

                try:
                    port_number = int(port_str)
                except ValueError:
                    continue

                ports = [
                    {
                        "port_number": port_number,
                        "protocol": protocol,
                        "state": state,
                    }
                ]

                if self._handle_host(scan.id, ip_address, ports, pending_out_of_scope):
                    processed_hosts += 1

        return processed_hosts

    # ------------------------------------------------------------------
    # Host handling helpers

    def _handle_host(
        self,
        scan_id: int,
        ip_address: str,
        ports: List[Dict[str, Any]],
        pending_out_of_scope: Dict[str, Dict[str, Any]],
    ) -> bool:
        if not ports:
            return False

        matching_subnets = self.correlation_service.parser.find_matching_subnets(ip_address)
        if matching_subnets:
            host_data = {
                "state": "up",
            }
            host = self.dedup_service.find_or_create_host(ip_address, scan_id, host_data)
            for port in ports:
                port_payload = {
                    "port_number": port["port_number"],
                    "protocol": port.get("protocol", "tcp"),
                    "state": port.get("state", "open"),
                }
                self.dedup_service.find_or_create_port(host.id, scan_id, port_payload)
            return True

        self._queue_out_of_scope(ip_address, ports, pending_out_of_scope)
        self._conditionally_flush_out_of_scope(scan_id, pending_out_of_scope)
        return False

    def _queue_out_of_scope(
        self,
        ip_address: str,
        ports: List[Dict[str, Any]],
        pending_out_of_scope: Dict[str, Dict[str, Any]],
    ) -> None:
        entry = pending_out_of_scope.setdefault(
            ip_address,
            {
                "ip_address": ip_address,
                "ports": {"masscan_ports": []},
                "tool_source": "masscan",
                "reason": "IP address not found in any defined subnet scope",
            },
        )

        for port in ports:
            entry["ports"]["masscan_ports"].append(
                {
                    "port": port["port_number"],
                    "protocol": port.get("protocol", "tcp"),
                    "state": port.get("state", "open"),
                }
            )

    def _conditionally_flush_out_of_scope(
        self,
        scan_id: int,
        pending_out_of_scope: Dict[str, Dict[str, Any]],
    ) -> None:
        if len(pending_out_of_scope) >= self.OUT_OF_SCOPE_BATCH_SIZE:
            self._flush_out_of_scope(scan_id, pending_out_of_scope)

    def _flush_out_of_scope(
        self,
        scan_id: int,
        pending_out_of_scope: Dict[str, Dict[str, Any]],
    ) -> None:
        if not pending_out_of_scope:
            return

        payload = [
            {
                "scan_id": scan_id,
                **entry,
            }
            for entry in pending_out_of_scope.values()
        ]
        self.db.bulk_insert_mappings(models.OutOfScopeHost, payload)
        pending_out_of_scope.clear()

    # ------------------------------------------------------------------
    # Utility helpers

    def _create_scan_record(self, filename: str) -> models.Scan:
        scan = models.Scan(
            filename=filename,
            scan_type="port_scan",
            tool_name="masscan",
            created_at=datetime.utcnow(),
        )
        self.db.add(scan)
        self.db.flush()
        return scan

    def _extract_xml_host(self, host_elem: etree._Element) -> Optional[Dict[str, Any]]:
        address_elem = host_elem.find("address")
        if address_elem is None:
            return None
        ip_address = address_elem.get("addr")
        if not ip_address:
            return None

        ports: List[Dict[str, Any]] = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                try:
                    port_number = int(port_elem.get("portid"))
                except (TypeError, ValueError):
                    continue
                protocol = port_elem.get("protocol", "tcp")
                state_elem = port_elem.find("state")
                state = state_elem.get("state") if state_elem is not None else "open"
                if state != "open":
                    continue
                ports.append(
                    {
                        "port_number": port_number,
                        "protocol": protocol,
                        "state": state,
                    }
                )

        if not ports:
            return None

        return {
            "ip_address": ip_address,
            "ports": ports,
        }

    def _iter_json_entries(self, file_path: str) -> Iterable[Dict[str, Any]]:
        decoder = json.JSONDecoder()
        buffer = ""
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            for chunk in handle:
                buffer += chunk.strip()
                while buffer:
                    buffer = buffer.lstrip(", \n\r\t[")
                    if not buffer:
                        break
                    if buffer.startswith("]"):
                        buffer = buffer[1:]
                        continue
                    try:
                        entry, index = decoder.raw_decode(buffer)
                    except json.JSONDecodeError:
                        break
                    yield entry
                    buffer = buffer[index:]
        buffer = buffer.strip(", \n\r\t[]")
        if buffer:
            try:
                entry, _ = decoder.raw_decode(buffer)
                yield entry
            except json.JSONDecodeError:
                logger.warning("Trailing JSON buffer ignored while parsing Masscan output")

    def _strip_namespace(self, tag: str) -> str:
        return tag.split("}", 1)[-1] if "}" in tag else tag

    def _clear_element(self, elem: etree._Element) -> None:
        parent = elem.getparent()
        elem.clear()
        if parent is not None:
            while elem.getprevious() is not None:
                del parent[0]

    def _parse_timestamp(self, timestamp: Optional[str]) -> Optional[datetime]:
        if not timestamp:
            return None
        try:
            return datetime.fromtimestamp(int(timestamp))
        except (ValueError, TypeError):
            return None
