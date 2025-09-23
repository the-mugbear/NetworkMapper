import logging
import sys
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1.api import api_router
from app.db.session import engine
from app.db import models
from app.db import models_risk
from app.db import models_auth
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)

logger = logging.getLogger(__name__)

# Create database tables
models.Base.metadata.create_all(bind=engine, checkfirst=True)
models_risk.Base.metadata.create_all(bind=engine, checkfirst=True)
models_auth.Base.metadata.create_all(bind=engine, checkfirst=True)

app = FastAPI(
    title="NetworkMapper API", 
    description="API for parsing and managing network scan results with service name filtering and reports",
    version="1.2.1",
)

# Set up CORS with more permissive configuration for debugging
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for debugging
    allow_credentials=False,  # Must be False when using wildcard origins
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Include API router
app.include_router(api_router, prefix="/api/v1")

@app.on_event("startup")
async def startup_event():
    logger.info("NetworkMapper API starting up...")
    logger.info(f"CORS origins: {settings.CORS_ORIGINS}")

    # Create default admin user if it doesn't exist
    from app.db.session import SessionLocal
    from app.db.models_auth import User, UserRole
    from app.core.security import get_password_hash

    with SessionLocal() as db:
        admin_user = db.query(User).filter(User.username == "admin").first()
        if not admin_user:
            logger.info("Creating default admin user...")
            admin_user = User(
                username="admin",
                email="admin@example.com",
                full_name="Administrator",
                hashed_password=get_password_hash("admin123"),
                role=UserRole.ADMIN,
                is_active=True
            )
            db.add(admin_user)
            db.commit()
            logger.info("Default admin user created successfully")
    
@app.get("/")
async def root():
    return {"message": "NetworkMapper API", "version": "1.2.1", "cors_origins": settings.CORS_ORIGINS}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}