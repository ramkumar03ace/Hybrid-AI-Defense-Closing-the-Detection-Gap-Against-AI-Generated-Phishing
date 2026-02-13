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


# --- URL Analysis Schemas ---

class URLAnalysisRequest(BaseModel):
    """Request schema for URL analysis."""
    url: str = Field(..., description="URL to analyze", min_length=1)


class URLResult(BaseModel):
    """Result for a single URL analysis."""
    url: str = Field(..., description="The analyzed URL")
    domain: str = Field(..., description="Extracted domain")
    is_suspicious: bool = Field(..., description="Whether the URL is suspicious")
    risk_score: float = Field(..., description="Risk score (0-1)", ge=0, le=1)
    flags: List[str] = Field(default_factory=list, description="List of suspicious indicators")
    domain_age_days: Optional[int] = Field(None, description="Domain age in days")
    registrar: Optional[str] = Field(None, description="Domain registrar")
    ssl_valid: Optional[bool] = Field(None, description="Whether SSL certificate is valid")
    ssl_issuer: Optional[str] = Field(None, description="SSL certificate issuer")
    vt_malicious: Optional[int] = Field(None, description="VirusTotal malicious count")


class URLAnalysisResponse(BaseModel):
    """Response for URL analysis."""
    results: List[URLResult] = Field(..., description="Analysis results per URL")
    total_urls: int = Field(..., description="Total URLs analyzed")
    suspicious_count: int = Field(..., description="Number of suspicious URLs")
    highest_risk: float = Field(..., description="Highest risk score found")


class FullAnalysisRequest(BaseModel):
    """Request schema for full email + URL analysis."""
    text: str = Field(..., description="Email body text", min_length=1)
    subject: Optional[str] = Field(None, description="Email subject line")


class FullAnalysisResponse(BaseModel):
    """Combined email text + URL analysis response."""
    # Text analysis
    text_analysis: EmailResponse = Field(..., description="ML text classification result")
    
    # URL analysis
    urls_found: int = Field(..., description="Number of URLs found in email")
    url_analysis: Optional[URLAnalysisResponse] = Field(None, description="URL analysis results")
    
    # Combined verdict
    overall_verdict: str = Field(..., description="SAFE, SUSPICIOUS, or PHISHING")
    overall_risk_score: float = Field(..., description="Combined risk score (0-1)")
    risk_factors: List[str] = Field(default_factory=list, description="Key risk factors")


# --- Deep Analysis Schemas (Web Crawler + Visual) ---

class CrawlResultSchema(BaseModel):
    """Crawl result for a single URL."""
    url: str = Field(..., description="Original URL")
    final_url: str = Field("", description="Final URL after redirects")
    status_code: Optional[int] = Field(None, description="HTTP status code")
    page_title: str = Field("", description="Page title")
    was_redirected: bool = Field(False, description="Whether URL was redirected")
    redirect_chain: List[str] = Field(default_factory=list, description="Redirect chain")
    has_login_form: bool = Field(False, description="Whether page has login form")
    has_password_field: bool = Field(False, description="Whether page has password field")
    screenshot_path: Optional[str] = Field(None, description="Path to screenshot")
    error: Optional[str] = Field(None, description="Error if crawl failed")


class VisualAnalysisSchema(BaseModel):
    """Visual analysis of a crawled page."""
    is_fake_login: bool = Field(False, description="Whether page is a fake login")
    risk_score: float = Field(0.0, description="Visual risk score (0-1)")
    impersonated_brand: Optional[str] = Field(None, description="Brand being impersonated")
    flags: List[str] = Field(default_factory=list, description="Suspicious indicators")


class LinkCheckSchema(BaseModel):
    """Result of link checking."""
    total_links: int = Field(0, description="Total links found")
    checked_links: int = Field(0, description="Links checked")
    suspicious_links: int = Field(0, description="Suspicious links found")
    risk_score: float = Field(0.0, description="Link risk score (0-1)")
    flags: List[str] = Field(default_factory=list, description="Suspicious indicators")


class DeepAnalysisRequest(BaseModel):
    """Request for deep analysis (text + URL + crawl + visual)."""
    text: str = Field(..., description="Email body text", min_length=1)
    subject: Optional[str] = Field(None, description="Email subject line")
    crawl_urls: bool = Field(True, description="Whether to crawl URLs with browser")
    take_screenshots: bool = Field(True, description="Whether to capture screenshots")


class DeepAnalysisResponse(BaseModel):
    """Full deep analysis combining all detection layers."""
    # Layer 1: Text classification
    text_analysis: EmailResponse = Field(..., description="ML classification")
    
    # Layer 2: URL static analysis
    urls_found: int = Field(0, description="URLs found in email")
    url_analysis: Optional[URLAnalysisResponse] = Field(None, description="URL analysis")
    
    # Layer 3: Web crawling
    crawl_results: List[CrawlResultSchema] = Field(default_factory=list, description="Crawl results")
    
    # Layer 4: Visual analysis
    visual_analysis: List[VisualAnalysisSchema] = Field(default_factory=list, description="Visual analysis")
    
    # Layer 5: Link checking
    link_analysis: Optional[LinkCheckSchema] = Field(None, description="Link checking")
    
    # Combined verdict
    overall_verdict: str = Field(..., description="SAFE, SUSPICIOUS, or PHISHING")
    overall_risk_score: float = Field(..., description="Combined risk score (0-1)")
    risk_factors: List[str] = Field(default_factory=list, description="Key risk factors")
    analysis_layers: List[str] = Field(default_factory=list, description="Layers that ran")

