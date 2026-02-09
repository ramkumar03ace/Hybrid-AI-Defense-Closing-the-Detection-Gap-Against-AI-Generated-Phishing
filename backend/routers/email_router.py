"""
Email analysis API router.
"""

from fastapi import APIRouter, HTTPException
from typing import List

from models.schemas import (
    EmailRequest,
    EmailResponse,
    BatchEmailRequest,
    BatchEmailResponse,
    HealthResponse
)
from services.email_classifier import classifier
from config import settings

router = APIRouter(prefix=settings.API_V1_PREFIX, tags=["Email Analysis"])


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Check the health status of the API and model.
    """
    return HealthResponse(
        status="healthy" if classifier.is_loaded() else "degraded",
        model_loaded=classifier.is_loaded(),
        version=settings.VERSION
    )


@router.post("/analyze", response_model=EmailResponse)
async def analyze_email(request: EmailRequest):
    """
    Analyze a single email for phishing detection.
    
    - **text**: The email body text to analyze
    - **subject**: Optional email subject line
    
    Returns the classification result with confidence score and risk level.
    """
    if not classifier.is_loaded():
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Please try again later."
        )
    
    try:
        is_phishing, confidence, label, risk_level = classifier.predict(
            text=request.text,
            subject=request.subject
        )
        
        return EmailResponse(
            is_phishing=is_phishing,
            confidence=round(confidence, 4),
            label=label,
            risk_level=risk_level
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error analyzing email: {str(e)}"
        )


@router.post("/batch", response_model=BatchEmailResponse)
async def analyze_batch(request: BatchEmailRequest):
    """
    Analyze multiple emails for phishing detection.
    
    - **emails**: List of emails to analyze
    
    Returns classification results for all emails with summary statistics.
    """
    if not classifier.is_loaded():
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Please try again later."
        )
    
    try:
        results: List[EmailResponse] = []
        phishing_count = 0
        
        for email in request.emails:
            is_phishing, confidence, label, risk_level = classifier.predict(
                text=email.text,
                subject=email.subject
            )
            
            results.append(EmailResponse(
                is_phishing=is_phishing,
                confidence=round(confidence, 4),
                label=label,
                risk_level=risk_level
            ))
            
            if is_phishing:
                phishing_count += 1
        
        return BatchEmailResponse(
            results=results,
            total=len(results),
            phishing_count=phishing_count,
            legitimate_count=len(results) - phishing_count
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error analyzing emails: {str(e)}"
        )
