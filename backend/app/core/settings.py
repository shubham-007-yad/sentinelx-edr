import os
from typing import List
from pydantic import BaseModel, Field, model_validator, field_validator
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseModel):
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "SentinelX EDR")
    VERSION: str = os.getenv("VERSION", "1.0.0")
    API_V1_STR: str = os.getenv("API_V1_STR", "/api/v1")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    @field_validator("API_V1_STR", mode="before")
    @classmethod
    def normalize_api_v1_str(cls, v: str) -> str:
        v = str(v or "/api/v1").strip().strip('"').strip("'")
        if not v.startswith("/"):
            v = "/" + v
        return v.rstrip("/")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    BACKEND_URL: str = os.getenv("BACKEND_URL", "http://localhost:8000")

    # Security & JWT Secrets
    SECRET_KEY: str = Field(
        default_factory=lambda: os.getenv("JWT_SECRET") or os.getenv("SECRET_KEY", "sentinelx-edr-super-secret-key-2026-production-ready")
    )
    @property
    def JWT_SECRET(self) -> str:
        return self.SECRET_KEY

    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))  # 24 hours

    # Database Settings
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "sentinel")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "sentinel")
    POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "localhost")
    POSTGRES_PORT: str = os.getenv("POSTGRES_PORT", "5433")
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "sentinelx")

    # Redis Settings
    REDIS_HOST: str = os.getenv("REDIS_HOST", "redis")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_PASSWORD: str = os.getenv("REDIS_PASSWORD", "")

    # CORS Settings
    CORS_ORIGINS_RAW: str = os.getenv(
        "CORS_ORIGINS",
        "http://localhost,http://localhost:5173,http://localhost:3000,http://localhost:8000,http://127.0.0.1:5173"
    )

    @property
    def CORS_ORIGINS(self) -> List[str]:
        if not self.CORS_ORIGINS_RAW:
            return ["*"]
        if self.CORS_ORIGINS_RAW.strip() == "*":
            return ["*"]
        return [origin.strip() for origin in self.CORS_ORIGINS_RAW.split(",") if origin.strip()]

    @property
    def DATABASE_URL(self) -> str:
        env_db_url = os.getenv("DATABASE_URL")
        if env_db_url:
            return env_db_url
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

    @property
    def REDIS_URL(self) -> str:
        env_redis_url = os.getenv("REDIS_URL")
        if env_redis_url:
            return env_redis_url
        if self.REDIS_PASSWORD:
            return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/0"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/0"

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        if self.ENVIRONMENT.lower() == "production":
            default_key = "sentinelx-edr-super-secret-key-2026-production-ready"
            if not self.SECRET_KEY or self.SECRET_KEY == default_key or len(self.SECRET_KEY) < 16:
                raise ValueError(
                    "CRITICAL SECURITY ERROR: In production environment, JWT_SECRET / SECRET_KEY "
                    "must be set to a strong custom secret (at least 16 chars). Do not use default or weak secrets!"
                )
        return self

settings = Settings()
