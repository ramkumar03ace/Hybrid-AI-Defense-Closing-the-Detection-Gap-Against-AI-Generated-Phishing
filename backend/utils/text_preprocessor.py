"""
Text preprocessing utilities for email analysis.
"""

import re
from typing import Optional


def clean_text(text: str) -> str:
    """
    Clean and preprocess email text for model input.
    
    Args:
        text: Raw email text
        
    Returns:
        Cleaned text ready for model inference
    """
    if not text:
        return ""
    
    # Convert to lowercase
    text = text.lower()
    
    # Replace URLs with placeholder
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    text = re.sub(url_pattern, '[URL]', text)
    
    # Replace email addresses with placeholder
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    text = re.sub(email_pattern, '[EMAIL]', text)
    
    # Replace phone numbers with placeholder
    phone_pattern = r'[\+]?[(]?[0-9]{1,3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}'
    text = re.sub(phone_pattern, '[PHONE]', text)
    
    # Remove excessive whitespace
    text = re.sub(r'\s+', ' ', text)
    
    # Strip leading/trailing whitespace
    text = text.strip()
    
    return text


def combine_subject_and_body(subject: Optional[str], body: str) -> str:
    """
    Combine email subject and body into a single text.
    
    Args:
        subject: Email subject line (optional)
        body: Email body text
        
    Returns:
        Combined text
    """
    if subject:
        return f"Subject: {subject}\n\n{body}"
    return body
