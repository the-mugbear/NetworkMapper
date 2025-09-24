import os
from typing import List

class Settings:
    # Database configuration
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql://nmapuser:nmappass@localhost:5432/networkMapper"
    )

    # Security settings
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    
    # CORS origins - read from environment variable, fall back to localhost
    @property
    def CORS_ORIGINS(self) -> List[str]:
        cors_env = os.getenv("CORS_ORIGINS")
        if cors_env:
            return [origin.strip() for origin in cors_env.split(",")]
        return [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ]
    
    # File upload settings
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", os.path.join(os.getcwd(), "uploads"))
    MAX_FILE_SIZE: int = int(os.getenv("MAX_FILE_SIZE", str(1024 * 1024 * 1024)))  # 1GB default
    UPLOAD_CHUNK_SIZE: int = int(os.getenv("UPLOAD_CHUNK_SIZE", str(5 * 1024 * 1024)))  # 5MB chunks
    INGESTION_STORAGE_DIR: str = os.getenv(
        "INGESTION_STORAGE_DIR",
        os.path.join(os.getcwd(), "uploads", "ingestion_queue")
    )
    INGESTION_WORKERS: int = int(os.getenv("INGESTION_WORKERS", "2"))

    # Nessus ingestion tuning
    NESSUS_COMMIT_BATCH_SIZE: int = int(os.getenv("NESSUS_COMMIT_BATCH_SIZE", "50"))
    NESSUS_PLUGIN_OUTPUT_MAX_CHARS: int = int(
        os.getenv("NESSUS_PLUGIN_OUTPUT_MAX_CHARS", str(32 * 1024))
    )
    
    # Supported file extensions for scan uploads
    ALLOWED_EXTENSIONS: List[str] = [
        ".xml",     # Nmap XML, Masscan XML, Nessus XML
        ".nessus",  # Nessus vulnerability scan files
        ".gnmap",   # Nmap grepable format
        ".json",    # Masscan JSON, Eyewitness JSON, NetExec JSON
        ".csv",     # Eyewitness CSV, DNS records CSV
        ".txt"      # Masscan list format, NetExec output
    ]

settings = Settings()
