"""
Email parser - extracts text, URLs, and headers from raw email content.
"""

import re
from typing import List, Optional
from dataclasses import dataclass, field


@dataclass
class ParsedEmail:
    """Parsed email data."""
    body: str = ""
    subject: Optional[str] = None
    sender: Optional[str] = None
    urls: List[str] = field(default_factory=list)
    has_html: bool = False
    has_attachments: bool = False


class EmailParser:
    """Parses email content to extract URLs, text, and metadata."""
    
    # URL patterns
    URL_PATTERN = re.compile(
        r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\-.~:/?#\[\]@!$&\'()*+,;=%]*',
        re.IGNORECASE
    )
    
    # Email pattern
    EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )
    
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """
        Extract all URLs from text, including links inside HTML tags.
        
        Args:
            text: Email body or raw content (plain text or HTML)
            
        Returns:
            List of unique URLs found
        """
        if not text:
            return []
        
        urls = []
        
        # 1. Extract URLs from HTML href attributes (catches links in images, buttons, etc.)
        href_pattern = re.compile(
            r'<a\s+[^>]*href\s*=\s*["\']([^"\']+)["\']',
            re.IGNORECASE
        )
        urls.extend(href_pattern.findall(text))
        
        # 2. Extract URLs from HTML src attributes (img, iframe, etc.)
        src_pattern = re.compile(
            r'<(?:img|iframe|source)\s+[^>]*src\s*=\s*["\']([^"\']+)["\']',
            re.IGNORECASE
        )
        src_urls = src_pattern.findall(text)
        # Only include src URLs that look like full links (not relative paths or data URIs)
        urls.extend([u for u in src_urls if u.startswith(('http://', 'https://'))])
        
        # 3. Extract URLs from plain text using regex
        urls.extend(EmailParser.URL_PATTERN.findall(text))
        
        # 4. Also catch common URL-like patterns without protocol
        bare_url_pattern = re.compile(
            r'\b(?:www\.)[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z]{2,})+[/\w\-.~:/?#\[\]@!$&\'()*+,;=%]*',
            re.IGNORECASE
        )
        bare_urls = bare_url_pattern.findall(text)
        urls.extend([f"http://{url}" for url in bare_urls])
        
        # Remove duplicates, preserve order
        seen = set()
        unique_urls = []
        for url in urls:
            clean_url = url.rstrip('.,;:!?)\'\">').strip()
            if clean_url and clean_url not in seen and clean_url.startswith(('http://', 'https://')):
                seen.add(clean_url)
                unique_urls.append(clean_url)
        
        return unique_urls
    
    @staticmethod
    def extract_sender(text: str) -> Optional[str]:
        """Extract sender email from text."""
        emails = EmailParser.EMAIL_PATTERN.findall(text)
        return emails[0] if emails else None
    
    @staticmethod
    def parse(text: str, subject: Optional[str] = None) -> ParsedEmail:
        """
        Parse email content into structured data.
        
        Args:
            text: Email body text
            subject: Optional subject line
            
        Returns:
            ParsedEmail with extracted data
        """
        urls = EmailParser.extract_urls(text)
        sender = EmailParser.extract_sender(text)
        has_html = bool(re.search(r'<[^>]+>', text))
        
        # Also extract URLs from subject
        if subject:
            subject_urls = EmailParser.extract_urls(subject)
            urls.extend(subject_urls)
        
        return ParsedEmail(
            body=text,
            subject=subject,
            sender=sender,
            urls=list(set(urls)),
            has_html=has_html
        )
