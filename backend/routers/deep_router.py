"""
Deep analysis API router - combines all detection layers.

Pipeline:
1. ML text classification (DistilBERT)
2. URL static analysis (WHOIS, SSL, VirusTotal, patterns)
3. Web crawling (Playwright headless browser + screenshots)
4. Visual analysis (fake login page detection)
5. Recursive link checking (redirects, domain changes)
"""

import asyncio
import logging
from fastapi import APIRouter, HTTPException

from models.schemas import (
    DeepAnalysisRequest,
    DeepAnalysisResponse,
    EmailResponse,
    URLResult,
    URLAnalysisResponse,
    CrawlResultSchema,
    VisualAnalysisSchema,
    LinkCheckSchema,
)
from analyzers.url_analyzer import url_analyzer
from analyzers.email_parser import EmailParser
from analyzers.web_crawler import web_crawler
from analyzers.visual_analyzer import visual_analyzer
from analyzers.link_checker import link_checker
from services.email_classifier import classifier
from config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix=settings.API_V1_PREFIX, tags=["Deep Analysis"])


@router.post("/deep-analyze", response_model=DeepAnalysisResponse)
async def deep_analysis(request: DeepAnalysisRequest):
    """
    Perform deep multi-layer analysis of an email.
    
    Combines 5 detection layers:
    1. **Text Classification** — DistilBERT ML model
    2. **URL Analysis** — WHOIS, SSL, VirusTotal, patterns
    3. **Web Crawling** — Visit URLs in headless browser, capture screenshots
    4. **Visual Analysis** — Detect fake login pages, brand impersonation
    5. **Link Checking** — Follow redirects, detect suspicious chains
    """
    if not classifier.is_loaded():
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Please try again later."
        )
    
    try:
        analysis_layers = []
        risk_factors = []
        
        # ==========================================
        # LAYER 1: Text Classification
        # ==========================================
        is_phishing, confidence, label, risk_level = classifier.predict(
            text=request.text,
            subject=request.subject
        )
        
        text_result = EmailResponse(
            is_phishing=is_phishing,
            confidence=round(confidence, 4),
            label=label,
            risk_level=risk_level
        )
        analysis_layers.append("text_classification")
        
        if is_phishing:
            risk_factors.append(f"Email text classified as phishing ({confidence:.1%} confidence)")
        
        # ==========================================
        # LAYER 2: URL Static Analysis
        # ==========================================
        parsed_email = EmailParser.parse(request.text, request.subject)
        urls = parsed_email.urls
        
        # Also extract URLs from raw HTML (captures href links on images, buttons, etc.)
        if request.email_html:
            html_urls = EmailParser.extract_urls(request.email_html)
            existing = set(urls)
            for u in html_urls:
                if u not in existing:
                    urls.append(u)
                    existing.add(u)
        
        url_response = None
        max_url_risk = 0.0
        
        if urls:
            url_results = url_analyzer.analyze_urls(urls)
            
            url_items = []
            suspicious_url_count = 0
            
            for r in url_results:
                url_items.append(URLResult(
                    url=r.url,
                    domain=r.domain,
                    is_suspicious=r.is_suspicious,
                    risk_score=round(r.risk_score, 4),
                    flags=r.flags,
                    domain_age_days=r.domain_age_days,
                    registrar=r.registrar,
                    ssl_valid=r.ssl_valid,
                    ssl_issuer=r.ssl_issuer,
                    vt_malicious=r.vt_malicious,
                ))
                
                if r.is_suspicious:
                    suspicious_url_count += 1
                    risk_factors.extend(r.flags[:2])
                
                max_url_risk = max(max_url_risk, r.risk_score)
            
            url_response = URLAnalysisResponse(
                results=url_items,
                total_urls=len(url_items),
                suspicious_count=suspicious_url_count,
                highest_risk=round(max_url_risk, 4)
            )
            analysis_layers.append("url_analysis")
        
        # ==========================================
        # LAYER 3: Web Crawling
        # ==========================================
        crawl_schemas = []
        visual_schemas = []
        max_visual_risk = 0.0
        
        # Crawl only runs when crawl toggle is enabled
        # (UI enforces: screenshots requires crawl to be on)
        should_crawl = urls and request.crawl_urls
        # Visual analysis only runs when screenshots are also enabled
        should_visual = request.take_screenshots
        
        if should_crawl:
            for url in urls[:5]:  # Limit to 5 URLs
                try:
                    crawl_result = await web_crawler.crawl_url(
                        url, 
                        take_screenshot=request.take_screenshots
                    )
                    
                    crawl_schemas.append(CrawlResultSchema(
                        url=crawl_result.url,
                        final_url=crawl_result.final_url,
                        status_code=crawl_result.status_code,
                        page_title=crawl_result.page_title,
                        was_redirected=crawl_result.was_redirected,
                        redirect_chain=crawl_result.redirect_chain,
                        has_login_form=crawl_result.has_login_form,
                        has_password_field=crawl_result.has_password_field,
                        screenshot_path=crawl_result.screenshot_path,
                        error=crawl_result.error,
                    ))
                    
                    # ==========================================
                    # LAYER 4: Visual Analysis (per crawled page)
                    # Only runs when screenshots are enabled
                    # ==========================================
                    if should_visual and not crawl_result.error:
                        visual_result = visual_analyzer.analyze(crawl_result)
                        
                        visual_schemas.append(VisualAnalysisSchema(
                            is_fake_login=visual_result.is_fake_login,
                            risk_score=round(visual_result.risk_score, 4),
                            impersonated_brand=visual_result.impersonated_brand,
                            flags=visual_result.flags,
                        ))
                        
                        max_visual_risk = max(max_visual_risk, visual_result.risk_score)
                        
                        if visual_result.is_fake_login:
                            brand = visual_result.impersonated_brand or "unknown"
                            risk_factors.append(f"Fake login page detected (impersonating {brand})")
                            risk_factors.extend(visual_result.flags[:2])
                    
                except Exception as e:
                    logger.error(f"Error in crawl/visual for {url}: {e}")
            
            if crawl_schemas:
                analysis_layers.append("web_crawling")
            if visual_schemas:
                analysis_layers.append("visual_analysis")
        
        # Compute crawl risk from crawl findings
        crawl_risk = 0.0
        if crawl_schemas:
            for cs in crawl_schemas:
                if cs.error:
                    continue
                if cs.has_password_field:
                    crawl_risk = max(crawl_risk, 0.7)
                    risk_factors.append("Password field detected on crawled page")
                elif cs.has_login_form:
                    crawl_risk = max(crawl_risk, 0.5)
                    risk_factors.append("Login form detected on crawled page")
                if cs.was_redirected:
                    crawl_risk = max(crawl_risk, 0.3)
        
        # ==========================================
        # LAYER 5: Link Checking
        # ==========================================
        link_schema = None
        link_risk = 0.0
        
        if urls:
            link_result = link_checker.check_links(urls)
            
            link_schema = LinkCheckSchema(
                total_links=link_result.total_links,
                checked_links=link_result.checked_links,
                suspicious_links=link_result.suspicious_links,
                risk_score=round(link_result.risk_score, 4),
                flags=link_result.flags,
            )
            
            link_risk = link_result.risk_score
            
            if link_result.suspicious_links > 0:
                risk_factors.extend(link_result.flags[:3])
            
            analysis_layers.append("link_checking")
        
        # ==========================================
        # COMBINED SCORING — Dynamic Weight Redistribution
        # ==========================================
        # Base weights (when all layers are active):
        #   Text:   15%
        #   URL:    25%
        #   Crawl:  10%
        #   Visual: 20%
        #   Links:  20%
        #
        # When a layer is disabled/skipped, its weight is
        # redistributed proportionally among active layers.
        text_risk = confidence if is_phishing else (1 - confidence)
        
        # Build active layers with their base weights
        active_scores = {}
        active_scores["text"] = (text_risk, 0.15)
        
        if url_response:
            active_scores["url"] = (max_url_risk, 0.25)
        
        if crawl_schemas:
            active_scores["crawl"] = (crawl_risk, 0.10)
        
        if visual_schemas:
            active_scores["visual"] = (max_visual_risk, 0.20)
        
        if link_schema:
            active_scores["links"] = (link_risk, 0.20)
        
        # Normalize weights so they sum to ~0.90 (matching original total)
        # then compute weighted sum
        total_base_weight = sum(w for _, w in active_scores.values())
        
        if total_base_weight > 0:
            combined_risk = sum(
                score * (weight / total_base_weight * 0.90)
                for score, weight in active_scores.values()
            )
        else:
            combined_risk = text_risk * 0.90
        
        # Boost if multiple layers flag it (2+ layers = +0.15)
        flagging_layers = sum([
            is_phishing,
            max_url_risk >= 0.30 if url_response else False,
            crawl_risk >= 0.40 if crawl_schemas else False,
            max_visual_risk >= 0.40 if visual_schemas else False,
            link_risk >= 0.30 if link_schema else False,
        ])
        if flagging_layers >= 2:
            combined_risk = min(1.0, combined_risk + 0.15)
        
        # Determine verdict
        if combined_risk >= 0.65:
            verdict = "PHISHING"
        elif combined_risk >= 0.30:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"
        
        return DeepAnalysisResponse(
            text_analysis=text_result,
            urls_found=len(urls),
            url_analysis=url_response,
            crawl_results=crawl_schemas,
            visual_analysis=visual_schemas,
            link_analysis=link_schema,
            overall_verdict=verdict,
            overall_risk_score=round(combined_risk, 4),
            risk_factors=list(dict.fromkeys(risk_factors)),  # Deduplicate
            analysis_layers=analysis_layers,
        )
        
    except Exception as e:
        logger.error(f"Deep analysis error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error during deep analysis: {str(e)}"
        )
