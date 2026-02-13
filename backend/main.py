"""
FastAPI backend for phishing email detection.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from config import settings
from routers import email_router
from routers import url_router
from services.email_classifier import classifier

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifecycle manager for the FastAPI application.
    Loads the model on startup.
    """
    logger.info("Starting up Phishing Detection API...")
    
    # Load the model
    if classifier.load_model():
        logger.info("Model loaded successfully!")
    else:
        logger.warning("Failed to load model. API will start in degraded mode.")
    
    yield
    
    # Cleanup on shutdown
    logger.info("Shutting down Phishing Detection API...")


# Create FastAPI app
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="""
    ## Phishing Email Detection API
    
    This API uses a fine-tuned DistilBERT model and URL analysis to detect phishing.
    
    ### Features
    - **Email text analysis**: ML-based classification with DistilBERT
    - **URL analysis**: WHOIS, SSL, VirusTotal, pattern detection
    - **Full analysis**: Combined text + URL verdict
    - **Batch analysis**: Analyze multiple emails in one request
    - **Risk levels**: Automatic risk classification (LOW, MEDIUM, HIGH)
    
    ### Model Information
    - Architecture: DistilBERT
    - Training Data: 9,600 emails (V2 dataset)
    - Test Accuracy: 99.17%
    """,
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
)

# Include routers
app.include_router(email_router.router)
app.include_router(url_router.router)


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": "/docs",
        "health": f"{settings.API_V1_PREFIX}/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG
    )
