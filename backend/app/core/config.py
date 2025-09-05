import os
from typing import List

class Settings:
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://nmapuser:nmappass@localhost:5432/networkMapper")
    
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
    UPLOAD_DIR: str = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "uploads"))
    MAX_FILE_SIZE: int = 50 * 1024 * 1024  # 50MB
    
    # Supported file extensions
    ALLOWED_EXTENSIONS: List[str] = [".xml"]

settings = Settings()