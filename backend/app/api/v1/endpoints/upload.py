import logging
from typing import List

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.api.v1.endpoints.auth import get_current_user
from app.db.models import IngestionJob
from app.db.models_auth import User
from app.db.session import get_db
from app.schemas.schemas import FileUploadResponse, IngestionJobSchema
from app.services.ingestion_service import ingestion_service

logger = logging.getLogger(__name__)

router = APIRouter()

ALLOWED_EXTENSIONS = {'.xml', '.json', '.csv', '.txt', '.gnmap', '.nessus'}


@router.post("/", response_model=FileUploadResponse)
async def upload_scan_file(
    file: UploadFile = File(...),
    enrich_dns: bool = False,
    dns_server: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")

    if not any(file.filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
        raise HTTPException(
            status_code=400,
            detail=(
                "File type not allowed. Supported types: "
                + ", ".join(sorted(ALLOWED_EXTENSIONS))
            ),
        )

    options = {"enrich_dns": enrich_dns}
    if dns_server:
        options["dns_server"] = dns_server

    try:
        job = await ingestion_service.create_job(
            db=db,
            upload=file,
            submitted_by_id=current_user.id if current_user else None,
            options=options,
        )
    except ValueError as exc:
        logger.warning("Upload rejected: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Failed to queue ingestion job")
        raise HTTPException(status_code=500, detail="Failed to queue ingestion job") from exc

    ingestion_service.enqueue_job(job.id)

    return FileUploadResponse(
        job_id=job.id,
        filename=job.original_filename,
        status=job.status,
        message="File queued for background processing",
        scan_id=None,
    )


@router.get("/jobs/{job_id}", response_model=IngestionJobSchema)
def get_ingestion_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    job = db.query(IngestionJob).filter(IngestionJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Ingestion job not found")
    return job


@router.get("/jobs", response_model=List[IngestionJobSchema])
def list_ingestion_jobs(
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    limit = max(1, min(limit, 50))
    jobs = (
        db.query(IngestionJob)
        .order_by(desc(IngestionJob.created_at))
        .limit(limit)
        .all()
    )
    return jobs
