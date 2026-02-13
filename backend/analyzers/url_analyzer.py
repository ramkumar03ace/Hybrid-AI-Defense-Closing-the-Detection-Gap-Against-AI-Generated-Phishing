"""
URL Analyzer - Checks URLs for phishing indicators.

Features:
- Domain age via WHOIS
- SSL certificate validation
- VirusTotal reputation (optional)
- Suspicious pattern detection
"""

import ssl
import socket
import re
import logging
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse
from dataclasses import dataclass, field
from datetime import datetime, timezone

import whois
import requests

from config import settings

logger = logging.getLogger(__name__)


@dataclass
class URLAnalysisResult:
    """Result of analyzing a single URL."""
    url: str
    domain: str
    is_suspicious: bool = False
    risk_score: float = 0.0  # 0-1 scale
    flags: List[str] = field(default_factory=list)
    
    # WHOIS data
    domain_age_days: Optional[int] = None
    registrar: Optional[str] = None
    whois_error: Optional[str] = None
    
    # SSL data
    ssl_valid: Optional[bool] = None
    ssl_issuer: Optional[str] = None
    ssl_expiry: Optional[str] = None
    ssl_error: Optional[str] = None
    
    # VirusTotal data
    vt_malicious: Optional[int] = None
    vt_suspicious: Optional[int] = None
    vt_harmless: Optional[int] = None
    vt_error: Optional[str] = None


class URLAnalyzer:
    """Analyzes URLs for phishing indicators."""
    
    # Known suspicious TLDs
    SUSPICIOUS_TLDS = {
        '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
        '.buzz', '.club', '.work', '.click', '.link', '.info',
        '.online', '.site', '.website', '.space', '.pw', '.cc'
    }
    
    # Brands commonly impersonated in phishing
    IMPERSONATED_BRANDS = {
        'google', 'microsoft', 'apple', 'amazon', 'paypal',
        'netflix', 'facebook', 'instagram', 'whatsapp', 'linkedin',
        'dropbox', 'chase', 'wellsfargo', 'bankofamerica', 'citibank',
        'outlook', 'office365', 'icloud', 'yahoo', 'twitter'
    }
    
    def __init__(self):
        self.vt_api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', None)
    
    def analyze_url(self, url: str) -> URLAnalysisResult:
        """
        Perform full analysis on a single URL.
        
        Args:
            url: URL to analyze
            
        Returns:
            URLAnalysisResult with all findings
        """
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        # Remove port if present
        domain = domain.split(':')[0]
        
        result = URLAnalysisResult(url=url, domain=domain)
        
        # Run all checks
        self._check_suspicious_patterns(result, parsed)
        self._check_whois(result, domain)
        self._check_ssl(result, domain)
        
        if self.vt_api_key:
            self._check_virustotal(result, url)
        
        # Calculate final risk score
        self._calculate_risk_score(result)
        
        return result
    
    def analyze_urls(self, urls: List[str]) -> List[URLAnalysisResult]:
        """Analyze multiple URLs."""
        results = []
        for url in urls:
            try:
                results.append(self.analyze_url(url))
            except Exception as e:
                logger.error(f"Error analyzing URL {url}: {e}")
                result = URLAnalysisResult(
                    url=url,
                    domain=urlparse(url).netloc or "unknown",
                    is_suspicious=True,
                    flags=[f"Analysis error: {str(e)}"]
                )
                results.append(result)
        return results
    
    def _check_suspicious_patterns(self, result: URLAnalysisResult, parsed) -> None:
        """Check URL for known suspicious patterns."""
        url_lower = result.url.lower()
        domain_lower = result.domain.lower()
        
        # Check for IP address instead of domain
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if ip_pattern.match(domain_lower):
            result.flags.append("URL uses IP address instead of domain name")
        
        # Check for suspicious TLD
        for tld in self.SUSPICIOUS_TLDS:
            if domain_lower.endswith(tld):
                result.flags.append(f"Suspicious TLD: {tld}")
                break
        
        # Check for brand impersonation
        for brand in self.IMPERSONATED_BRANDS:
            if brand in domain_lower and brand not in self._get_legitimate_domains(brand):
                result.flags.append(f"Possible brand impersonation: {brand}")
                break
        
        # Check for excessive subdomains (e.g., secure.login.account.paypal.phishing.com)
        subdomain_count = domain_lower.count('.')
        if subdomain_count >= 3:
            result.flags.append(f"Excessive subdomains ({subdomain_count} dots)")
        
        # Check for URL length
        if len(result.url) > 200:
            result.flags.append("Unusually long URL")
        
        # Check for @ symbol (used to trick users)
        if '@' in result.url:
            result.flags.append("URL contains @ symbol (possible redirection trick)")
        
        # Check for double slashes in path (not protocol)
        path = parsed.path
        if '//' in path:
            result.flags.append("Double slashes in URL path")
        
        # Check for homograph/typosquatting patterns
        suspicious_chars = {'0': 'o', '1': 'l', '3': 'e', '5': 's'}
        for char, letter in suspicious_chars.items():
            if char in domain_lower:
                result.flags.append(f"Possible homograph: '{char}' may substitute '{letter}'")
                break
        
        # Check for HTTPS
        if parsed.scheme == 'http':
            result.flags.append("Not using HTTPS")
    
    def _get_legitimate_domains(self, brand: str) -> set:
        """Return known legitimate domains for common brands."""
        legit_domains = {
            'google': {'google.com', 'google.co.in', 'googleapis.com'},
            'microsoft': {'microsoft.com', 'live.com', 'outlook.com'},
            'apple': {'apple.com', 'icloud.com'},
            'amazon': {'amazon.com', 'amazon.in', 'amazonaws.com'},
            'paypal': {'paypal.com'},
            'facebook': {'facebook.com', 'fb.com'},
            'instagram': {'instagram.com'},
        }
        return legit_domains.get(brand, set())
    
    def _check_whois(self, result: URLAnalysisResult, domain: str) -> None:
        """Check domain WHOIS data for age and registrar."""
        try:
            w = whois.whois(domain)
            
            # Get creation date
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                # Calculate domain age
                now = datetime.now(timezone.utc)
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                age = (now - creation_date).days
                result.domain_age_days = age
                
                # Flag young domains
                if age < 30:
                    result.flags.append(f"Very new domain ({age} days old)")
                elif age < 180:
                    result.flags.append(f"Recently registered domain ({age} days old)")
            
            # Get registrar
            if w.registrar:
                result.registrar = w.registrar
                
        except Exception as e:
            result.whois_error = str(e)
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
    
    def _check_ssl(self, result: URLAnalysisResult, domain: str) -> None:
        """Check SSL certificate validity."""
        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=domain
            )
            conn.settimeout(5.0)
            conn.connect((domain, 443))
            
            cert = conn.getpeercert()
            conn.close()
            
            result.ssl_valid = True
            
            # Get issuer
            issuer = dict(x[0] for x in cert.get('issuer', []))
            result.ssl_issuer = issuer.get('organizationName', 'Unknown')
            
            # Get expiry
            not_after = cert.get('notAfter')
            if not_after:
                result.ssl_expiry = not_after
                # Check if certificate is about to expire
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (expiry_date - datetime.utcnow()).days
                if days_until_expiry < 7:
                    result.flags.append(f"SSL certificate expiring in {days_until_expiry} days")
                    
        except ssl.SSLCertVerificationError as e:
            result.ssl_valid = False
            result.ssl_error = "Invalid SSL certificate"
            result.flags.append("Invalid SSL certificate")
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
            result.ssl_valid = None
            result.ssl_error = f"Cannot connect: {str(e)}"
        except Exception as e:
            result.ssl_error = str(e)
            logger.debug(f"SSL check failed for {domain}: {e}")
    
    def _check_virustotal(self, result: URLAnalysisResult, url: str) -> None:
        """Check URL against VirusTotal API."""
        try:
            headers = {"x-apikey": self.vt_api_key}
            
            # First, submit URL for analysis
            payload = {"url": url}
            response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                analysis_id = response.json()["data"]["id"]
                
                # Get analysis results
                result_response = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers,
                    timeout=10
                )
                
                if result_response.status_code == 200:
                    stats = result_response.json()["data"]["attributes"]["stats"]
                    result.vt_malicious = stats.get("malicious", 0)
                    result.vt_suspicious = stats.get("suspicious", 0)
                    result.vt_harmless = stats.get("harmless", 0)
                    
                    if result.vt_malicious and result.vt_malicious > 0:
                        result.flags.append(
                            f"VirusTotal: {result.vt_malicious} security vendors flagged as malicious"
                        )
                    if result.vt_suspicious and result.vt_suspicious > 0:
                        result.flags.append(
                            f"VirusTotal: {result.vt_suspicious} vendors flagged as suspicious"
                        )
            else:
                result.vt_error = f"API returned status {response.status_code}"
                
        except Exception as e:
            result.vt_error = str(e)
            logger.debug(f"VirusTotal check failed for {url}: {e}")
    
    def _calculate_risk_score(self, result: URLAnalysisResult) -> None:
        """Calculate overall risk score (0-1) based on all findings."""
        score = 0.0
        
        # Pattern-based scoring
        pattern_weights = {
            "IP address": 0.20,
            "Suspicious TLD": 0.15,
            "brand impersonation": 0.25,
            "Excessive subdomains": 0.10,
            "Unusually long URL": 0.05,
            "@ symbol": 0.15,
            "Double slashes": 0.05,
            "homograph": 0.15,
            "Not using HTTPS": 0.10,
        }
        
        for flag in result.flags:
            for keyword, weight in pattern_weights.items():
                if keyword.lower() in flag.lower():
                    score += weight
                    break
        
        # Domain age scoring
        if result.domain_age_days is not None:
            if result.domain_age_days < 30:
                score += 0.25
            elif result.domain_age_days < 180:
                score += 0.10
        
        # SSL scoring
        if result.ssl_valid is False:
            score += 0.20
        
        # VirusTotal scoring
        if result.vt_malicious and result.vt_malicious > 0:
            score += min(0.30, result.vt_malicious * 0.05)
        
        # Cap at 1.0
        result.risk_score = min(1.0, score)
        result.is_suspicious = result.risk_score >= 0.30


# Global instance
url_analyzer = URLAnalyzer()
