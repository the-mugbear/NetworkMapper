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
    MAX_FILE_SIZE: int = int(os.getenv("MAX_FILE_SIZE", str(100 * 1024 * 1024)))  # 100MB default
    
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