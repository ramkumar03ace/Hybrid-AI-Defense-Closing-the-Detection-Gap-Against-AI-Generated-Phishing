"""
Web Crawler - Safely visits URLs using Playwright headless browser.

Uses multiprocessing to run Playwright in a separate process,
avoiding async event loop conflicts with FastAPI/uvicorn on Windows.
"""

import asyncio
import logging
import multiprocessing
from typing import Optional, List
from dataclasses import dataclass, field
from pathlib import Path

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
    """Safely crawls URLs using Playwright in a separate process."""
    
    def __init__(self, timeout: int = 30):
        """
        Args:
            timeout: Process timeout in seconds
        """
        self.timeout = timeout
    
    async def crawl_url(self, url: str, take_screenshot: bool = True) -> CrawlResult:
        """
        Visit a URL safely via a separate process running Playwright.
        Uses multiprocessing to completely isolate from FastAPI's event loop.
        """
        result = CrawlResult(url=url)
        
        try:
            # Import the worker function
            from analyzers.crawl_worker import crawl_to_queue
            
            # Create a queue for results
            result_queue = multiprocessing.Queue()
            
            # Spawn a new process
            process = multiprocessing.Process(
                target=crawl_to_queue,
                args=(url, str(SCREENSHOTS_DIR), take_screenshot, result_queue),
            )
            process.start()
            
            # Wait for result with timeout (run blocking wait in executor)
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(
                None,
                self._wait_for_result,
                process,
                result_queue,
                self.timeout,
            )
            
            if data is None:
                result.error = f"Crawl timed out after {self.timeout}s"
                process.kill()
                return result
            
            # Map data to CrawlResult
            result.final_url = data.get("final_url", "")
            result.status_code = data.get("status_code")
            result.page_title = data.get("page_title", "")
            result.has_login_form = data.get("has_login_form", False)
            result.has_password_field = data.get("has_password_field", False)
            result.input_fields = data.get("input_fields", [])
            result.form_actions = data.get("form_actions", [])
            result.external_links = data.get("external_links", [])
            result.was_redirected = data.get("was_redirected", False)
            result.redirect_chain = data.get("redirect_chain", [])
            result.screenshot_path = data.get("screenshot_path")
            result.page_text = data.get("page_text", "")
            result.error = data.get("error")
            
        except Exception as e:
            result.error = str(e) or "Unknown crawl error"
            logger.error(f"Crawl error for {url}: {e}")
        
        return result
    
    def _wait_for_result(self, process, result_queue, timeout):
        """Wait for the crawl process to finish and return result."""
        process.join(timeout=timeout)
        
        if process.is_alive():
            process.kill()
            process.join(timeout=5)
            return None
        
        try:
            if not result_queue.empty():
                return result_queue.get_nowait()
        except Exception:
            pass
        
        return None


# Global instance
web_crawler = WebCrawler()
