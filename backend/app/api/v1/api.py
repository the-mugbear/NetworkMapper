from fastapi import APIRouter
from app.api.v1.endpoints import scans, hosts, dashboard, upload, scopes, export, dns, parse_errors, reports, auth, risk, audit, users

api_router = APIRouter()

# Authentication routes (no auth required)
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])

# Protected routes (require authentication)
api_router.include_router(upload.router, prefix="/upload", tags=["upload"])
api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
api_router.include_router(hosts.router, prefix="/hosts", tags=["hosts"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(scopes.router, prefix="/scopes", tags=["scopes"])
api_router.include_router(export.router, prefix="/export", tags=["export"])
api_router.include_router(dns.router, prefix="/dns", tags=["dns"])
api_router.include_router(parse_errors.router, prefix="/parse-errors", tags=["parse-errors"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(risk.router, prefix="/risk", tags=["risk"])
api_router.include_router(audit.router, prefix="/audit", tags=["audit"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
