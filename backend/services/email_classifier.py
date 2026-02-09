"""
Email classifier service using DistilBERT model.
"""

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from typing import Tuple, Optional
import logging

from config import settings
from utils.text_preprocessor import clean_text, combine_subject_and_body

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EmailClassifier:
    """
    Singleton class for email classification using DistilBERT.
    """
    
    _instance: Optional["EmailClassifier"] = None
    _initialized: bool = False
    
    def __new__(cls) -> "EmailClassifier":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self.model = None
        self.tokenizer = None
        self.device = None
        self._initialized = True
    
    def load_model(self) -> bool:
        """
        Load the DistilBERT model and tokenizer.
        
        Returns:
            True if model loaded successfully, False otherwise
        """
        try:
            model_path = settings.MODEL_PATH
            
            if not model_path.exists():
                logger.error(f"Model path does not exist: {model_path}")
                return False
            
            logger.info(f"Loading model from: {model_path}")
            
            # Load tokenizer and model
            self.tokenizer = AutoTokenizer.from_pretrained(str(model_path))
            self.model = AutoModelForSequenceClassification.from_pretrained(str(model_path))
            
            # Set device (GPU if available)
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.model.to(self.device)
            self.model.eval()
            
            logger.info(f"Model loaded successfully on device: {self.device}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False
    
    def is_loaded(self) -> bool:
        """Check if the model is loaded."""
        return self.model is not None and self.tokenizer is not None
    
    def predict(self, text: str, subject: Optional[str] = None) -> Tuple[bool, float, str, str]:
        """
        Predict if an email is phishing or legitimate.
        
        Args:
            text: Email body text
            subject: Optional email subject
            
        Returns:
            Tuple of (is_phishing, confidence, label, risk_level)
        """
        if not self.is_loaded():
            raise RuntimeError("Model not loaded. Call load_model() first.")
        
        # Preprocess text
        combined_text = combine_subject_and_body(subject, text)
        cleaned_text = clean_text(combined_text)
        
        # Tokenize
        inputs = self.tokenizer(
            cleaned_text,
            return_tensors="pt",
            truncation=True,
            max_length=settings.MAX_TEXT_LENGTH,
            padding=True
        )
        
        # Remove token_type_ids if present (DistilBERT doesn't use them)
        if "token_type_ids" in inputs:
            del inputs["token_type_ids"]
        
        # Move to device
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        # Predict
        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
            pred = torch.argmax(probs, dim=-1).item()
            confidence = probs[0][pred].item()
        
        # Determine label and risk level
        is_phishing = pred == 1
        label = "PHISHING" if is_phishing else "LEGITIMATE"
        
        if is_phishing:
            if confidence >= settings.HIGH_RISK_THRESHOLD:
                risk_level = "HIGH"
            elif confidence >= settings.MEDIUM_RISK_THRESHOLD:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"
        else:
            risk_level = "LOW"
        
        return is_phishing, confidence, label, risk_level


# Global classifier instance
classifier = EmailClassifier()
