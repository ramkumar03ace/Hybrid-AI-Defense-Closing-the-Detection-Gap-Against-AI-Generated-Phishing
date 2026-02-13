"""
URL analysis API router.
"""

from fastapi import APIRouter, HTTPException
from typing import List

from models.schemas import (
    URLAnalysisRequest,
    URLResult,
    URLAnalysisResponse,
    FullAnalysisRequest,
    FullAnalysisResponse,
    EmailResponse,
)
from analyzers.url_analyzer import url_analyzer
from analyzers.email_parser import EmailParser
from services.email_classifier import classifier
from config import settings

router = APIRouter(prefix=settings.API_V1_PREFIX, tags=["URL Analysis"])


@router.post("/analyze-url", response_model=URLAnalysisResponse)
async def analyze_url(request: URLAnalysisRequest):
    """
    Analyze a single URL for phishing indicators.
    
    Checks:
    - Suspicious patterns (IP address, typosquatting, etc.)
    - Domain age via WHOIS
    - SSL certificate validity
    - VirusTotal reputation (if API key configured)
    """
    try:
        result = url_analyzer.analyze_url(request.url)
        
        url_result = URLResult(
            url=result.url,
            domain=result.domain,
            is_suspicious=result.is_suspicious,
            risk_score=round(result.risk_score, 4),
            flags=result.flags,
            domain_age_days=result.domain_age_days,
            registrar=result.registrar,
            ssl_valid=result.ssl_valid,
            ssl_issuer=result.ssl_issuer,
            vt_malicious=result.vt_malicious,
        )
        
        return URLAnalysisResponse(
            results=[url_result],
            total_urls=1,
            suspicious_count=1 if result.is_suspicious else 0,
            highest_risk=round(result.risk_score, 4)
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error analyzing URL: {str(e)}"
        )


@router.post("/full-analyze", response_model=FullAnalysisResponse)
async def full_analysis(request: FullAnalysisRequest):
    """
    Perform full analysis: ML text classification + URL analysis.
    
    This endpoint:
    1. Classifies email text using DistilBERT
    2. Extracts all URLs from the email
    3. Analyzes each URL for phishing indicators
    4. Combines results into an overall verdict
    """
    if not classifier.is_loaded():
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Please try again later."
        )
    
    try:
        # 1. Text classification
        is_phishing, confidence, label, risk_level = classifier.predict(
            text=request.text,
            subject=request.subject
        )
        
        text_result = EmailResponse(
            is_phishing=is_phishing,
            confidence=round(confidence, 4),
            label=label,
            risk_level=risk_level
        )
        
        # 2. Extract URLs
        parsed = EmailParser.parse(request.text, request.subject)
        urls = parsed.urls
        
        # 3. Analyze URLs (if any found)
        url_response = None
        url_risk_factors = []
        max_url_risk = 0.0
        
        if urls:
            url_results = url_analyzer.analyze_urls(urls)
            
            url_result_items = []
            suspicious_count = 0
            
            for r in url_results:
                url_result_items.append(URLResult(
                    url=r.url,
                    domain=r.domain,
                    is_suspicious=r.is_suspicious,
                    risk_score=round(r.risk_score, 4),
                    flags=r.flags,
                    domain_age_days=r.domain_age_days,
                    registrar=r.registrar,
                    ssl_valid=r.ssl_valid,
                    ssl_issuer=r.ssl_issuer,
                    vt_malicious=r.vt_malicious,
                ))
                
                if r.is_suspicious:
                    suspicious_count += 1
                    url_risk_factors.extend(r.flags[:3])  # Top 3 flags per URL
                
                max_url_risk = max(max_url_risk, r.risk_score)
            
            url_response = URLAnalysisResponse(
                results=url_result_items,
                total_urls=len(url_result_items),
                suspicious_count=suspicious_count,
                highest_risk=round(max_url_risk, 4)
            )
        
        # 4. Calculate combined verdict
        risk_factors = []
        
        if is_phishing:
            risk_factors.append(f"Email text classified as phishing ({confidence:.1%} confidence)")
        
        risk_factors.extend(url_risk_factors)
        
        # Combined risk score: 60% text, 40% URL
        text_risk = confidence if is_phishing else (1 - confidence)
        combined_risk = (text_risk * 0.6) + (max_url_risk * 0.4)
        
        # Determine verdict
        if combined_risk >= 0.70:
            verdict = "PHISHING"
        elif combined_risk >= 0.35:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"
        
        return FullAnalysisResponse(
            text_analysis=text_result,
            urls_found=len(urls),
            url_analysis=url_response,
            overall_verdict=verdict,
            overall_risk_score=round(combined_risk, 4),
            risk_factors=risk_factors
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error during full analysis: {str(e)}"
        )
