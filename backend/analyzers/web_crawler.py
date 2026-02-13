"""
Web Crawler - Safely visits URLs using Playwright headless browser.

Features:
- Headless Chromium browsing in sandbox mode
- Screenshot capture of visited pages
- Page content extraction (title, forms, inputs)
- Timeout and safety controls
"""

import asyncio
import logging
import os
import uuid
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Screenshot storage directory
SCREENSHOTS_DIR = Path(__file__).parent.parent / "screenshots"
SCREENSHOTS_DIR.mkdir(exist_ok=True)


@dataclass
class CrawlResult:
    """Result of crawling a single URL."""
    url: str
    final_url: str = ""
    status_code: Optional[int] = None
    page_title: str = ""
    
    # Page content analysis
    has_login_form: bool = False
    has_password_field: bool = False
    input_fields: List[str] = field(default_factory=list)
    form_actions: List[str] = field(default_factory=list)
    external_links: List[str] = field(default_factory=list)
    
    # Redirect info
    was_redirected: bool = False
    redirect_chain: List[str] = field(default_factory=list)
    
    # Screenshot
    screenshot_path: Optional[str] = None
    
    # Meta
    page_text: str = ""
    error: Optional[str] = None


class WebCrawler:
    """Safely crawls URLs using Playwright headless browser."""
    
    def __init__(self, timeout: int = 15000):
        """
        Args:
            timeout: Page load timeout in milliseconds
        """
        self.timeout = timeout
    
    async def crawl_url(self, url: str, take_screenshot: bool = True) -> CrawlResult:
        """
        Visit a URL safely in a sandboxed headless browser.
        
        Args:
            url: URL to visit
            take_screenshot: Whether to capture a screenshot
            
        Returns:
            CrawlResult with page analysis
        """
        from playwright.async_api import async_playwright
        
        result = CrawlResult(url=url)
        redirect_chain = [url]
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-gpu',
                        '--disable-extensions',
                        '--disable-plugins',
                    ]
                )
                
                context = await browser.new_context(
                    viewport={'width': 1280, 'height': 720},
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    java_script_enabled=True,
                    ignore_https_errors=True,
                )
                
                page = await context.new_page()
                
                # Track redirects
                page.on("response", lambda response: redirect_chain.append(response.url) if response.status in [301, 302, 303, 307, 308] else None)
                
                # Navigate to URL
                response = None
                try:
                    response = await page.goto(url, wait_until='domcontentloaded', timeout=self.timeout)
                except Exception as nav_error:
                    error_msg = str(nav_error)
                    # If HTTPS failed, try HTTP fallback
                    if url.startswith('https://'):
                        http_url = url.replace('https://', 'http://', 1)
                        logger.info(f"HTTPS failed for {url}, trying HTTP fallback")
                        try:
                            response = await page.goto(http_url, wait_until='domcontentloaded', timeout=self.timeout)
                        except Exception:
                            result.error = f"Navigation failed (HTTPS and HTTP): {error_msg}"
                    else:
                        result.error = f"Navigation failed: {error_msg}"
                
                if response:
                    result.status_code = response.status
                
                result.final_url = page.url or ""
                
                # Check if page actually loaded
                page_loaded = (
                    result.final_url 
                    and result.final_url not in ('', 'about:blank')
                    and result.status_code is not None
                )
                
                if page_loaded:
                    result.page_title = await page.title() or ""
                    
                    # Check for redirects
                    if result.final_url != url:
                        result.was_redirected = True
                        result.redirect_chain = redirect_chain
                    
                    # Analyze page content
                    await self._analyze_page(page, result)
                    
                    # Take screenshot
                    if take_screenshot:
                        try:
                            screenshot_name = f"{uuid.uuid4().hex[:12]}.png"
                            screenshot_path = SCREENSHOTS_DIR / screenshot_name
                            await page.screenshot(path=str(screenshot_path), full_page=False)
                            result.screenshot_path = str(screenshot_path)
                        except Exception as ss_error:
                            logger.warning(f"Screenshot failed for {url}: {ss_error}")
                elif not result.error:
                    result.error = "Page failed to load (no response received)"
                
                await browser.close()
                
        except Exception as e:
            error_msg = str(e) or "Unknown error during crawl"
            result.error = error_msg
            logger.error(f"Error crawling {url}: {e}")
        
        return result
    
    async def _analyze_page(self, page, result: CrawlResult) -> None:
        """Extract and analyze page content."""
        try:
            # Check for password fields
            password_fields = await page.query_selector_all('input[type="password"]')
            result.has_password_field = len(password_fields) > 0
            
            # Check for login forms
            forms = await page.query_selector_all('form')
            for form in forms:
                action = await form.get_attribute('action') or ''
                result.form_actions.append(action)
                
                # Check for login-related inputs
                inputs = await form.query_selector_all('input')
                for inp in inputs:
                    input_type = await inp.get_attribute('type') or 'text'
                    input_name = await inp.get_attribute('name') or ''
                    result.input_fields.append(f"{input_type}:{input_name}")
            
            # Detect login form
            result.has_login_form = result.has_password_field or any(
                keyword in str(result.input_fields).lower()
                for keyword in ['email', 'username', 'user', 'login', 'signin']
            )
            
            # Get external links
            links = await page.query_selector_all('a[href]')
            current_domain = urlparse(result.final_url).netloc
            for link in links[:50]:  # Limit to 50 links
                href = await link.get_attribute('href')
                if href and href.startswith('http'):
                    link_domain = urlparse(href).netloc
                    if link_domain != current_domain:
                        result.external_links.append(href)
            
            # Get page text (limited)
            result.page_text = (await page.inner_text('body'))[:2000]
            
        except Exception as e:
            logger.debug(f"Error analyzing page: {e}")


# Global instance
web_crawler = WebCrawler()
