"""
URL Analyzer - Analyzes URLs found in emails for phishing indicators.

Components:
- URL extraction from email text
- WHOIS domain age lookup
- SSL certificate verification
- VirusTotal integration (optional)
- Combined risk scoring
"""

from .url_analyzer import URLAnalyzer
from .email_parser import EmailParser
