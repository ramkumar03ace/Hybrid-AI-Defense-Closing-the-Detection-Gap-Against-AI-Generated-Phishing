"""
Email classifier service using cybersectony/phishing-email-detection-distilbert_v2.4.1
from HuggingFace Hub.
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

# Label mapping for cybersectony/phishing-email-detection-distilbert_v2.4.1
# Index 0: legitimate_email, 1: phishing_url, 2: legitimate_url, 3: phishing_url_alt
LABEL_NAMES = ["legitimate_email", "phishing_url", "legitimate_url", "phishing_url_alt"]
PHISHING_LABEL_INDICES = {1, 3}  # phishing_url and phishing_url_alt


class EmailClassifier:
    """
    Singleton class for email classification using HuggingFace DistilBERT model.
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
        Load the DistilBERT model and tokenizer from HuggingFace Hub.

        Returns:
            True if model loaded successfully, False otherwise
        """
        try:
            model_id = settings.HF_MODEL_ID
            logger.info(f"Loading model from HuggingFace Hub: {model_id}")

            # Load tokenizer and model from HuggingFace Hub
            self.tokenizer = AutoTokenizer.from_pretrained(model_id)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_id)

            # Set device (GPU if available)
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.model.to(self.device)
            self.model.eval()

            logger.info(f"Model '{model_id}' loaded successfully on device: {self.device}")
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

        The model outputs 4 classes:
            0: legitimate_email
            1: phishing_url
            2: legitimate_url
            3: phishing_url_alt

        Classes 1 and 3 are treated as phishing; 0 and 2 as legitimate.

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

        # Move to device
        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        # Predict
        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
            pred = torch.argmax(probs, dim=-1).item()
            confidence = probs[0][pred].item()

        # Determine if phishing based on winning label
        is_phishing = pred in PHISHING_LABEL_INDICES
        predicted_label_name = LABEL_NAMES[pred]

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

        logger.debug(
            f"Prediction: {predicted_label_name} ({label}), "
            f"Confidence: {confidence:.4f}, Risk: {risk_level}"
        )

        return is_phishing, confidence, label, risk_level


# Global classifier instance
classifier = EmailClassifier()
