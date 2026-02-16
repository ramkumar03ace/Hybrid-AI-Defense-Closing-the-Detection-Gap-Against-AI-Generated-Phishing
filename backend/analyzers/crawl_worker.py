"""
Crawl Worker - Standalone script that runs Playwright in its own process.
Called by web_crawler.py via multiprocessing to avoid event loop conflicts.

This worker uses multiprocessing.Queue to return results instead of
stdout/stderr, avoiding Windows pipe issues entirely.
"""

import sys
import json
import uuid
import logging
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def crawl(url: str, screenshot_dir: str, take_screenshot: bool = True) -> dict:
    """Crawl a URL and return results as a dict."""
    from playwright.sync_api import sync_playwright
    
    result = {
        "url": url,
        "final_url": "",
        "status_code": None,
        "page_title": "",
        "has_login_form": False,
        "has_password_field": False,
        "input_fields": [],
        "form_actions": [],
        "external_links": [],
        "was_redirected": False,
        "redirect_chain": [],
        "screenshot_path": None,
        "page_text": "",
        "error": None,
    }
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-extensions',
                    '--disable-plugins',
                ]
            )
            
            context = browser.new_context(
                viewport={'width': 1280, 'height': 720},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                java_script_enabled=True,
                ignore_https_errors=True,
            )
            
            page = context.new_page()
            
            # Navigate
            response = None
            try:
                response = page.goto(url, wait_until='domcontentloaded', timeout=15000)
            except Exception as nav_error:
                error_msg = str(nav_error)
                if url.startswith('https://'):
                    http_url = url.replace('https://', 'http://', 1)
                    try:
                        response = page.goto(http_url, wait_until='domcontentloaded', timeout=15000)
                    except Exception:
                        result["error"] = f"Navigation failed (HTTPS and HTTP): {error_msg}"
                else:
                    result["error"] = f"Navigation failed: {error_msg}"
            
            if response:
                result["status_code"] = response.status
            
            result["final_url"] = page.url or ""
            
            page_loaded = (
                result["final_url"]
                and result["final_url"] not in ('', 'about:blank')
                and result["status_code"] is not None
            )
            
            if page_loaded:
                result["page_title"] = page.title() or ""
                
                if result["final_url"] != url:
                    result["was_redirected"] = True
                
                # Analyze forms
                try:
                    password_fields = page.query_selector_all('input[type="password"]')
                    result["has_password_field"] = len(password_fields) > 0
                    
                    forms = page.query_selector_all('form')
                    for form in forms:
                        action = form.get_attribute('action') or ''
                        result["form_actions"].append(action)
                        inputs = form.query_selector_all('input')
                        for inp in inputs:
                            itype = inp.get_attribute('type') or 'text'
                            iname = inp.get_attribute('name') or ''
                            result["input_fields"].append(f"{itype}:{iname}")
                    
                    result["has_login_form"] = result["has_password_field"] or any(
                        k in str(result["input_fields"]).lower()
                        for k in ['email', 'username', 'user', 'login', 'signin']
                    )
                    
                    # External links
                    links = page.query_selector_all('a[href]')
                    current_domain = urlparse(result["final_url"]).netloc
                    for link in links[:50]:
                        href = link.get_attribute('href')
                        if href and href.startswith('http'):
                            link_domain = urlparse(href).netloc
                            if link_domain != current_domain:
                                result["external_links"].append(href)
                    
                    # Page text
                    try:
                        result["page_text"] = page.inner_text('body')[:2000]
                    except Exception:
                        result["page_text"] = ""
                        
                except Exception as e:
                    pass  # Continue even if analysis fails
                
                # Screenshot
                if take_screenshot:
                    try:
                        ss_dir = Path(screenshot_dir)
                        ss_dir.mkdir(exist_ok=True)
                        screenshot_name = f"{uuid.uuid4().hex[:12]}.png"
                        screenshot_path = ss_dir / screenshot_name
                        page.screenshot(path=str(screenshot_path), full_page=False)
                        result["screenshot_path"] = str(screenshot_path)
                    except Exception as ss_err:
                        result["error"] = f"Screenshot failed: {ss_err}"
                        
            elif not result["error"]:
                result["error"] = "Page failed to load (no response received)"
            
            browser.close()
            
    except Exception as e:
        result["error"] = str(e) or "Unknown crawl error"
    
    return result


def crawl_to_queue(url, screenshot_dir, take_screenshot, result_queue):
    """Entry point for multiprocessing - puts result in queue."""
    try:
        data = crawl(url, screenshot_dir, take_screenshot)
        result_queue.put(data)
    except Exception as e:
        result_queue.put({
            "url": url, "final_url": "", "status_code": None,
            "page_title": "", "has_login_form": False,
            "has_password_field": False, "input_fields": [],
            "form_actions": [], "external_links": [],
            "was_redirected": False, "redirect_chain": [],
            "screenshot_path": None, "page_text": "",
            "error": f"Worker process error: {type(e).__name__}: {str(e)}"
        })
