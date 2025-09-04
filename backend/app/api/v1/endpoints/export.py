from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.services.export_service import ExportService

router = APIRouter()

@router.get("/scope/{scope_id}")
async def export_scope_report(
    scope_id: int,
    format_type: str = Query(default="json", regex="^(json|csv|html)$"),
    db: Session = Depends(get_db)
):
    """Export comprehensive report for a scope"""
    try:
        export_service = ExportService(db)
        report = export_service.export_scope_report(scope_id, format_type)
        
        return Response(
            content=report['data'] if isinstance(report['data'], str) else str(report['data']),
            media_type=report['content_type'],
            headers={
                "Content-Disposition": f"attachment; filename={report['filename']}"
            }
        )
    
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")

@router.get("/scan/{scan_id}")
async def export_scan_report(
    scan_id: int,
    format_type: str = Query(default="json", regex="^(json|csv|html)$"),
    db: Session = Depends(get_db)
):
    """Export report for a specific scan"""
    try:
        export_service = ExportService(db)
        report = export_service.export_scan_report(scan_id, format_type)
        
        return Response(
            content=report['data'] if isinstance(report['data'], str) else str(report['data']),
            media_type=report['content_type'],
            headers={
                "Content-Disposition": f"attachment; filename={report['filename']}"
            }
        )
    
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")

@router.get("/out-of-scope")
async def export_out_of_scope_report(
    format_type: str = Query(default="json", regex="^(json|csv|html)$"),
    db: Session = Depends(get_db)
):
    """Export report of all out-of-scope findings"""
    try:
        export_service = ExportService(db)
        report = export_service.export_out_of_scope_report(format_type)
        
        return Response(
            content=report['data'] if isinstance(report['data'], str) else str(report['data']),
            media_type=report['content_type'],
            headers={
                "Content-Disposition": f"attachment; filename={report['filename']}"
            }
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")