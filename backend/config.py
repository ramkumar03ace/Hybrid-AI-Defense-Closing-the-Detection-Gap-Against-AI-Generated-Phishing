"""
Configuration settings for the phishing detection backend.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""
    
    # API Settings
    API_V1_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "Phishing Detection API"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Model Settings
    HF_MODEL_ID: str = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
    MAX_TEXT_LENGTH: int = 512
    
    # Classification Thresholds
    HIGH_RISK_THRESHOLD: float = 0.85
    MEDIUM_RISK_THRESHOLD: float = 0.50
    
    # URL Analysis
    VIRUSTOTAL_API_KEY: str = ""  # Optional: set in .env for URL reputation checks
    
    # CORS Settings
    CORS_ORIGINS: list = ["*"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: list = ["*"]
    CORS_ALLOW_HEADERS: list = ["*"]
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# Global settings instance
settings = Settings()
