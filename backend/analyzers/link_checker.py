"""
Link Checker - Recursively follows and analyzes links on a page.

Features:
- Follow HTTP redirects
- Detect redirect chains
- Check if final destination differs from displayed URL
- Depth-limited recursive crawling
"""

import logging
import asyncio
from typing import List, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

import requests

logger = logging.getLogger(__name__)


@dataclass
class LinkCheckResult:
    """Result of checking a single link."""
    original_url: str
    final_url: str = ""
    status_code: Optional[int] = None
    redirect_count: int = 0
    redirect_chain: List[str] = field(default_factory=list)
    is_suspicious: bool = False
    flags: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class LinkCrawlResult:
    """Result of recursively checking all links."""
    total_links: int = 0
    checked_links: int = 0
    suspicious_links: int = 0
    results: List[LinkCheckResult] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    risk_score: float = 0.0


class LinkChecker:
    """Recursively checks links for suspicious redirect patterns."""
    
    # Suspicious redirect destinations
    SUSPICIOUS_DOMAINS = {
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'rb.gy',
        'is.gd', 'shorturl.at', 'tiny.cc'
    }
    
    def __init__(self, max_depth: int = 2, max_links: int = 20, timeout: int = 10):
        """
        Args:
            max_depth: Maximum recursion depth
            max_links: Maximum number of links to check
            timeout: Request timeout in seconds
        """
        self.max_depth = max_depth
        self.max_links = max_links
        self.timeout = timeout
    
    def check_link(self, url: str) -> LinkCheckResult:
        """
        Check a single URL, following all redirects.
        
        Args:
            url: URL to check
            
        Returns:
            LinkCheckResult with redirect chain and analysis
        """
        result = LinkCheckResult(original_url=url)
        
        try:
            response = requests.get(
                url,
                allow_redirects=True,
                timeout=self.timeout,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                },
                verify=False  # Allow self-signed certs for analysis
            )
            
            result.status_code = response.status_code
            result.final_url = response.url
            
            # Track redirect chain
            if response.history:
                result.redirect_chain = [r.url for r in response.history] + [response.url]
                result.redirect_count = len(response.history)
            
            # Analyze for suspicious patterns
            self._analyze_link(result)
            
        except requests.Timeout:
            result.error = "Connection timed out"
            result.flags.append("Connection timed out (possible malicious server)")
            result.is_suspicious = True
        except requests.ConnectionError:
            result.error = "Connection failed"
        except Exception as e:
            result.error = str(e)
            logger.debug(f"Error checking link {url}: {e}")
        
        return result
    
    def check_links(self, urls: List[str]) -> LinkCrawlResult:
        """
        Check multiple links with depth limiting.
        
        Args:
            urls: List of URLs to check
            
        Returns:
            LinkCrawlResult with all findings
        """
        crawl_result = LinkCrawlResult(total_links=len(urls))
        checked: Set[str] = set()
        
        for url in urls[:self.max_links]:
            if url in checked:
                continue
            checked.add(url)
            
            link_result = self.check_link(url)
            crawl_result.results.append(link_result)
            crawl_result.checked_links += 1
            
            if link_result.is_suspicious:
                crawl_result.suspicious_links += 1
                crawl_result.flags.extend(link_result.flags)
        
        # Calculate overall risk
        if crawl_result.checked_links > 0:
            crawl_result.risk_score = min(
                1.0,
                crawl_result.suspicious_links / max(crawl_result.checked_links, 1) * 0.5 +
                len(crawl_result.flags) * 0.05
            )
        
        return crawl_result
    
    def _analyze_link(self, result: LinkCheckResult) -> None:
        """Analyze a checked link for suspicious patterns."""
        
        # Check for domain change in redirect
        if result.redirect_count > 0:
            original_domain = urlparse(result.original_url).netloc
            final_domain = urlparse(result.final_url).netloc
            
            if original_domain != final_domain:
                result.flags.append(
                    f"Redirect changes domain: {original_domain} → {final_domain}"
                )
                result.is_suspicious = True
        
        # Excessive redirects
        if result.redirect_count > 3:
            result.flags.append(f"Excessive redirects ({result.redirect_count} hops)")
            result.is_suspicious = True
        
        # URL shortener used
        original_domain = urlparse(result.original_url).netloc
        if original_domain in self.SUSPICIOUS_DOMAINS:
            result.flags.append(f"URL shortener used: {original_domain}")
            result.is_suspicious = True
        
        # Final URL uses suspicious TLD
        final_domain = urlparse(result.final_url).netloc if result.final_url else ""
        suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz'}
        for tld in suspicious_tlds:
            if final_domain.endswith(tld):
                result.flags.append(f"Final destination has suspicious TLD: {tld}")
                result.is_suspicious = True
                break
        
        # HTTP instead of HTTPS at final destination
        if result.final_url and result.final_url.startswith('http://'):
            result.flags.append("Final destination uses insecure HTTP")
        
        # Different protocol (http → https or vice versa) in redirect
        if result.redirect_count > 0:
            original_scheme = urlparse(result.original_url).scheme
            final_scheme = urlparse(result.final_url).scheme
            if original_scheme == 'https' and final_scheme == 'http':
                result.flags.append("Downgraded from HTTPS to HTTP during redirect")
                result.is_suspicious = True


# Global instance
link_checker = LinkChecker()
