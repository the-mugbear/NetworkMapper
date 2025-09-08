import logging
import sys
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1.api import api_router
from app.db.session import engine
from app.db import models

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
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="NetworkMapper API",
    description="API for parsing and managing network scan results with service name filtering and reports",
    version="1.2.0",
)

# Set up CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router
app.include_router(api_router, prefix="/api/v1")

@app.on_event("startup")
async def startup_event():
    logger.info("NetworkMapper API starting up...")
    logger.info(f"CORS origins: {settings.CORS_ORIGINS}")
    
@app.get("/")
async def root():
    return {"message": "NetworkMapper API", "version": "1.2.0"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}