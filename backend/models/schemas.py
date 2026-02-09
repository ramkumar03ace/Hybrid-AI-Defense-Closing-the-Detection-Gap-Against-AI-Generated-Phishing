"""
Pydantic schemas for API request/response models.
"""

from typing import Optional, List
from pydantic import BaseModel, Field


class EmailRequest(BaseModel):
    """Request schema for email analysis."""
    
    text: str = Field(..., description="Email body text to analyze", min_length=1)
    subject: Optional[str] = Field(None, description="Optional email subject line")
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "text": "Dear Customer, Your account has been compromised. Click here to verify.",
                    "subject": "Urgent: Account Security Alert"
                }
            ]
        }
    }


class EmailResponse(BaseModel):
    """Response schema for email analysis."""
    
    is_phishing: bool = Field(..., description="Whether the email is classified as phishing")
    confidence: float = Field(..., description="Model confidence score (0-1)", ge=0, le=1)
    label: str = Field(..., description="Classification label: PHISHING or LEGITIMATE")
    risk_level: str = Field(..., description="Risk level: LOW, MEDIUM, or HIGH")
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "is_phishing": True,
                    "confidence": 0.9981,
                    "label": "PHISHING",
                    "risk_level": "HIGH"
                }
            ]
        }
    }


class BatchEmailRequest(BaseModel):
    """Request schema for batch email analysis."""
    
    emails: List[EmailRequest] = Field(..., description="List of emails to analyze", min_length=1)


class BatchEmailResponse(BaseModel):
    """Response schema for batch email analysis."""
    
    results: List[EmailResponse] = Field(..., description="Analysis results for each email")
    total: int = Field(..., description="Total number of emails analyzed")
    phishing_count: int = Field(..., description="Number of emails classified as phishing")
    legitimate_count: int = Field(..., description="Number of emails classified as legitimate")


class HealthResponse(BaseModel):
    """Response schema for health check."""
    
    status: str = Field(..., description="Service status")
    model_loaded: bool = Field(..., description="Whether the ML model is loaded")
    version: str = Field(..., description="API version")
