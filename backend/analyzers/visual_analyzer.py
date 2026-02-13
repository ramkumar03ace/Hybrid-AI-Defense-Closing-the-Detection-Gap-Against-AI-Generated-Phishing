"""
Visual Analyzer - Detects fake login pages and phishing visual indicators.

Uses heuristic analysis of page content to determine if a webpage
is attempting to impersonate a legitimate login page.
"""

import re
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# Known brand signatures for detection
BRAND_SIGNATURES = {
    'google': {
        'titles': ['sign in', 'google accounts', 'gmail'],
        'keywords': ['google', 'gmail', '@gmail.com'],
        'legitimate_domains': ['google.com', 'accounts.google.com', 'gmail.com'],
    },
    'microsoft': {
        'titles': ['sign in', 'microsoft', 'outlook', 'office 365'],
        'keywords': ['microsoft', 'outlook', 'office', '@outlook.com', '@hotmail.com'],
        'legitimate_domains': ['microsoft.com', 'live.com', 'outlook.com', 'office.com'],
    },
    'apple': {
        'titles': ['apple id', 'sign in', 'icloud'],
        'keywords': ['apple id', 'icloud', '@icloud.com'],
        'legitimate_domains': ['apple.com', 'icloud.com'],
    },
    'paypal': {
        'titles': ['log in', 'paypal'],
        'keywords': ['paypal', 'payment', 'wallet'],
        'legitimate_domains': ['paypal.com'],
    },
    'amazon': {
        'titles': ['sign in', 'amazon'],
        'keywords': ['amazon', 'prime', 'aws'],
        'legitimate_domains': ['amazon.com', 'amazon.in', 'aws.amazon.com'],
    },
    'facebook': {
        'titles': ['log in', 'facebook', 'meta'],
        'keywords': ['facebook', 'meta', 'fb'],
        'legitimate_domains': ['facebook.com', 'fb.com', 'meta.com'],
    },
    'netflix': {
        'titles': ['sign in', 'netflix'],
        'keywords': ['netflix', 'streaming'],
        'legitimate_domains': ['netflix.com'],
    },
    'linkedin': {
        'titles': ['sign in', 'linkedin'],
        'keywords': ['linkedin', 'professional'],
        'legitimate_domains': ['linkedin.com'],
    },
    'instagram': {
        'titles': ['log in', 'instagram'],
        'keywords': ['instagram', 'insta'],
        'legitimate_domains': ['instagram.com'],
    },
    'twitter': {
        'titles': ['log in', 'x', 'twitter'],
        'keywords': ['twitter', 'tweet', 'x.com'],
        'legitimate_domains': ['twitter.com', 'x.com'],
    },
    'chase': {
        'titles': ['sign in', 'chase'],
        'keywords': ['chase', 'jpmorgan', 'banking'],
        'legitimate_domains': ['chase.com'],
    },
    'wellsfargo': {
        'titles': ['sign on', 'wells fargo'],
        'keywords': ['wells fargo', 'banking'],
        'legitimate_domains': ['wellsfargo.com'],
    },
}


@dataclass
class VisualAnalysisResult:
    """Result of visual/content analysis."""
    is_fake_login: bool = False
    confidence: float = 0.0
    risk_score: float = 0.0
    impersonated_brand: Optional[str] = None
    flags: List[str] = field(default_factory=list)
    
    # Page details
    has_login_form: bool = False
    has_password_field: bool = False
    brand_matches: List[str] = field(default_factory=list)
    suspicious_elements: List[str] = field(default_factory=list)


class VisualAnalyzer:
    """Analyzes page content to detect fake login pages."""
    
    def analyze(self, crawl_result) -> VisualAnalysisResult:
        """
        Analyze a crawled page for fake login indicators.
        
        Args:
            crawl_result: CrawlResult from WebCrawler
            
        Returns:
            VisualAnalysisResult with findings
        """
        result = VisualAnalysisResult(
            has_login_form=crawl_result.has_login_form,
            has_password_field=crawl_result.has_password_field,
        )
        
        url = crawl_result.final_url or crawl_result.url
        domain = urlparse(url).netloc.lower()
        page_title = crawl_result.page_title.lower() if crawl_result.page_title else ""
        page_text = crawl_result.page_text.lower() if crawl_result.page_text else ""
        
        # Run all checks
        self._check_brand_impersonation(result, domain, page_title, page_text)
        self._check_suspicious_forms(result, crawl_result)
        self._check_page_content(result, page_title, page_text, domain)
        self._check_redirect_tricks(result, crawl_result)
        
        # Calculate final scores
        self._calculate_scores(result)
        
        return result
    
    def _check_brand_impersonation(
        self, result: VisualAnalysisResult, domain: str, title: str, text: str
    ) -> None:
        """Check if page impersonates a known brand."""
        for brand, signatures in BRAND_SIGNATURES.items():
            brand_score = 0
            
            # Check title
            for brand_title in signatures['titles']:
                if brand_title in title:
                    brand_score += 1
            
            # Check page text
            for keyword in signatures['keywords']:
                if keyword in text:
                    brand_score += 1
            
            # If brand is detected, check if domain is legitimate
            if brand_score >= 2:
                is_legit_domain = any(
                    domain == legit or domain.endswith('.' + legit)
                    for legit in signatures['legitimate_domains']
                )
                
                if not is_legit_domain:
                    result.brand_matches.append(brand)
                    result.impersonated_brand = brand
                    result.flags.append(
                        f"Page impersonates {brand.title()} but hosted on {domain}"
                    )
    
    def _check_suspicious_forms(
        self, result: VisualAnalysisResult, crawl_result
    ) -> None:
        """Analyze form elements for phishing indicators."""
        
        # Password field on non-legitimate domain
        if crawl_result.has_password_field:
            result.suspicious_elements.append("Password input field detected")
        
        # Form submits to different domain
        for action in crawl_result.form_actions:
            if action and action.startswith('http'):
                form_domain = urlparse(action).netloc
                page_domain = urlparse(crawl_result.final_url or crawl_result.url).netloc
                if form_domain != page_domain:
                    result.flags.append(
                        f"Form submits data to external domain: {form_domain}"
                    )
                    result.suspicious_elements.append("Cross-domain form submission")
        
        # Check for credential harvesting patterns
        credential_inputs = [
            inp for inp in crawl_result.input_fields
            if any(k in inp.lower() for k in ['password', 'pass', 'pwd', 'email', 'user', 'login', 'ssn', 'card', 'credit'])
        ]
        if len(credential_inputs) >= 2:
            result.flags.append(
                f"Multiple credential input fields: {', '.join(credential_inputs[:5])}"
            )
    
    def _check_page_content(
        self, result: VisualAnalysisResult, title: str, text: str, domain: str
    ) -> None:
        """Analyze text content for phishing patterns."""
        
        # Urgency language
        urgency_words = [
            'verify your', 'confirm your identity', 'account suspended',
            'unusual activity', 'security alert', 'action required',
            'expires in', 'within 24 hours', 'immediately',
            'unauthorized access', 'account will be locked'
        ]
        found_urgency = [w for w in urgency_words if w in text]
        if found_urgency:
            result.flags.append(f"Urgency language detected: {', '.join(found_urgency[:3])}")
        
        # Data theft language
        data_theft_words = [
            'social security', 'ssn', 'credit card', 'card number',
            'cvv', 'expiry date', 'bank account', 'routing number',
            'mother\'s maiden', 'date of birth'
        ]
        found_data = [w for w in data_theft_words if w in text]
        if found_data:
            result.flags.append(f"Requests sensitive data: {', '.join(found_data[:3])}")
        
        # Page title mismatch with domain
        for brand_name, sigs in BRAND_SIGNATURES.items():
            if any(t in title for t in sigs['titles']):
                is_legit = any(
                    domain == d or domain.endswith('.' + d)
                    for d in sigs['legitimate_domains']
                )
                if not is_legit and result.has_login_form:
                    result.flags.append(
                        f"Login page title suggests {brand_name.title()} but domain is {domain}"
                    )
    
    def _check_redirect_tricks(
        self, result: VisualAnalysisResult, crawl_result
    ) -> None:
        """Check for suspicious redirect patterns."""
        if crawl_result.was_redirected:
            original_domain = urlparse(crawl_result.url).netloc
            final_domain = urlparse(crawl_result.final_url).netloc
            
            if original_domain != final_domain:
                result.flags.append(
                    f"Redirected to different domain: {original_domain} → {final_domain}"
                )
            
            if len(crawl_result.redirect_chain) > 3:
                result.flags.append(
                    f"Multiple redirects ({len(crawl_result.redirect_chain)} hops)"
                )
    
    def _calculate_scores(self, result: VisualAnalysisResult) -> None:
        """Calculate confidence and risk scores."""
        score = 0.0
        
        # Brand impersonation is highest signal
        if result.impersonated_brand:
            score += 0.35
        
        # Login form + password = credential harvesting
        if result.has_login_form and result.has_password_field:
            score += 0.20
        elif result.has_password_field:
            score += 0.10
        
        # Flag-based scoring
        flag_weights = {
            'impersonates': 0.15,
            'external domain': 0.15,
            'credential input': 0.15,
            'urgency': 0.10,
            'sensitive data': 0.15,
            'redirected': 0.10,
            'multiple redirects': 0.05,
        }
        
        for flag in result.flags:
            for keyword, weight in flag_weights.items():
                if keyword.lower() in flag.lower():
                    score += weight
                    break
        
        result.risk_score = min(1.0, score)
        result.is_fake_login = result.risk_score >= 0.40
        result.confidence = result.risk_score


# Global instance
visual_analyzer = VisualAnalyzer()
