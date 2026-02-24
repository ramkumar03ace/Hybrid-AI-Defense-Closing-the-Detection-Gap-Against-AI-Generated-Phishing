/* ============================================
   HYBRID AI DEFENSE — Frontend Logic
   ============================================ */

const API_BASE = 'http://localhost:8001/api/v1';

// ---------- DOM Refs ----------
const $ = (sel) => document.querySelector(sel);
const statusChip = $('#statusChip');
const analyzeBtn = $('#analyzeBtn');
const emailInput = $('#emailInput');
const subjectInput = $('#subjectInput');
const crawlToggle = $('#crawlToggle');
const screenshotToggle = $('#screenshotToggle');
const resultsSection = $('#resultsSection');
const verdictBanner = $('#verdictBanner');
const verdictText = $('#verdictText');
const layersBadges = $('#layersBadges');
const gaugeFill = $('#gaugeFill');
const gaugeScore = $('#gaugeScore');
const errorToast = $('#errorToast');
const riskFactorsCard = $('#riskFactorsCard');
const riskFactorsList = $('#riskFactorsList');

// Layer refs
const layers = {
    text: { score: $('#textScore'), bar: $('#textBar'), flags: $('#textFlags') },
    url: { score: $('#urlScore'), bar: $('#urlBar'), flags: $('#urlFlags') },
    crawl: { score: $('#crawlScore'), bar: $('#crawlBar'), flags: $('#crawlFlags') },
    visual: { score: $('#visualScore'), bar: $('#visualBar'), flags: $('#visualFlags') },
    links: { score: $('#linkScore'), bar: $('#linkBar'), flags: $('#linkFlags') },
};

// ---------- Health Check ----------
async function checkHealth() {
    try {
        const res = await fetch(`${API_BASE}/health`);
        const data = await res.json();
        if (data.model_loaded) {
            statusChip.textContent = '● API Online — Model Loaded';
            statusChip.className = 'status-chip status-chip--online';
        } else {
            statusChip.textContent = '● API Degraded — Model Not Loaded';
            statusChip.className = 'status-chip status-chip--offline';
        }
    } catch {
        statusChip.textContent = '● API Offline';
        statusChip.className = 'status-chip status-chip--offline';
    }
}

// ---------- Toast ----------
let toastTimer;
function showError(msg) {
    errorToast.textContent = msg;
    errorToast.classList.add('visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => errorToast.classList.remove('visible'), 5000);
}

// ---------- Color Helpers ----------
function verdictClass(verdict) {
    if (verdict === 'PHISHING') return 'phishing';
    if (verdict === 'SUSPICIOUS') return 'suspicious';
    return 'safe';
}

function scoreColorClass(score) {
    if (score >= 0.65) return 'phishing';
    if (score >= 0.30) return 'suspicious';
    return 'safe';
}

function verdictHex(verdict) {
    if (verdict === 'PHISHING') return '#ff1744';
    if (verdict === 'SUSPICIOUS') return '#ffab00';
    return '#00e676';
}

// ---------- Gauge ----------
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 40; // r=40

function setGauge(score, verdict) {
    const offset = GAUGE_CIRCUMFERENCE * (1 - score);
    gaugeFill.style.strokeDashoffset = offset;
    gaugeFill.style.stroke = verdictHex(verdict);
    // Animate score number
    animateNumber(gaugeScore, score);
}

function animateNumber(el, target) {
    const duration = 1000;
    const start = performance.now();
    const from = 0;
    function tick(now) {
        const progress = Math.min((now - start) / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 3);
        const val = from + (target - from) * ease;
        el.textContent = (val * 100).toFixed(0) + '%';
        if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
}

// ---------- Layer Card Helpers ----------
function setLayerCard(layerRef, score, flagsArr) {
    const cls = scoreColorClass(score);
    layerRef.score.textContent = (score * 100).toFixed(0) + '%';
    layerRef.score.className = `layer-card__score score-${cls}`;
    layerRef.bar.className = `layer-card__bar-fill bar-${cls}`;
    // Trigger animation after a frame
    requestAnimationFrame(() => {
        layerRef.bar.style.width = `${Math.max(score * 100, 2)}%`;
    });
    layerRef.flags.innerHTML = '';
    (flagsArr || []).forEach(f => {
        const li = document.createElement('li');
        li.textContent = f;
        layerRef.flags.appendChild(li);
    });
}

function resetLayerCard(layerRef) {
    layerRef.score.textContent = '—';
    layerRef.score.className = 'layer-card__score';
    layerRef.bar.style.width = '0';
    layerRef.bar.className = 'layer-card__bar-fill';
    layerRef.flags.innerHTML = '<li style="color:var(--text-muted);opacity:0.5;">No data</li>';
}

// ---------- Render Results ----------
function renderResults(data) {
    // Show section
    resultsSection.classList.add('visible');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Verdict banner
    const vc = verdictClass(data.overall_verdict);
    verdictBanner.className = `verdict-banner ${vc}`;
    verdictText.textContent = data.overall_verdict;

    // Gauge
    setGauge(data.overall_risk_score, data.overall_verdict);

    // Layer badges
    const layerNames = {
        text_classification: '🧠 Text',
        url_analysis: '🔗 URL',
        web_crawling: '🕷️ Crawl',
        visual_analysis: '👁️ Visual',
        link_checking: '🔀 Links',
    };
    layersBadges.innerHTML = (data.analysis_layers || [])
        .map(l => `<span>${layerNames[l] || l}</span>`)
        .join('');

    // --- Layer 1: Text ---
    const textConf = data.text_analysis.confidence;
    const textRisk = data.text_analysis.is_phishing ? textConf : (1 - textConf);
    const textFlags = [];
    textFlags.push(`Label: ${data.text_analysis.label}`);
    textFlags.push(`Confidence: ${(textConf * 100).toFixed(1)}%`);
    textFlags.push(`Risk Level: ${data.text_analysis.risk_level}`);
    setLayerCard(layers.text, textRisk, textFlags);

    // --- Layer 2: URL ---
    if (data.url_analysis && data.url_analysis.results.length > 0) {
        const urlRisk = data.url_analysis.highest_risk;
        const urlFlags = [];
        urlFlags.push(`${data.url_analysis.total_urls} URL(s) found, ${data.url_analysis.suspicious_count} suspicious`);
        data.url_analysis.results.forEach(r => {
            if (r.flags && r.flags.length > 0) {
                r.flags.slice(0, 3).forEach(f => urlFlags.push(f));
            }
        });
        // Show found URLs
        if (data.urls_list && data.urls_list.length > 0) {
            urlFlags.push('── URLs Found ──');
            data.urls_list.forEach(u => urlFlags.push(u));
        }
        setLayerCard(layers.url, urlRisk, urlFlags);
    } else {
        // Still show URLs found even if no URL analysis
        if (data.urls_list && data.urls_list.length > 0) {
            const urlFlags = [`${data.urls_list.length} URL(s) found`, '── URLs Found ──'];
            data.urls_list.forEach(u => urlFlags.push(u));
            setLayerCard(layers.url, 0, urlFlags);
        } else {
            resetLayerCard(layers.url);
        }
    }

    // --- Layer 3: Crawl ---
    if (data.crawl_results && data.crawl_results.length > 0) {
        const crawlFlags = [];
        let maxCrawlRisk = 0;
        data.crawl_results.forEach(c => {
            if (c.error) {
                crawlFlags.push(`❌ ${c.url}: ${c.error}`);
            } else {
                crawlFlags.push(`${c.page_title || 'Untitled'} — ${c.final_url}`);
                if (c.has_login_form) { crawlFlags.push('⚠️ Login form detected'); maxCrawlRisk = Math.max(maxCrawlRisk, 0.5); }
                if (c.has_password_field) { crawlFlags.push('⚠️ Password field detected'); maxCrawlRisk = Math.max(maxCrawlRisk, 0.6); }
                if (c.was_redirected) { crawlFlags.push(`↪ Redirected (${c.redirect_chain.length} hops)`); maxCrawlRisk = Math.max(maxCrawlRisk, 0.3); }
            }
        });
        setLayerCard(layers.crawl, maxCrawlRisk, crawlFlags);
    } else {
        resetLayerCard(layers.crawl);
    }

    // --- Layer 4: Visual ---
    if (data.visual_analysis && data.visual_analysis.length > 0) {
        const maxVisRisk = Math.max(...data.visual_analysis.map(v => v.risk_score));
        const visFlags = [];
        data.visual_analysis.forEach(v => {
            if (v.is_fake_login) visFlags.push(`🚨 Fake login page — ${v.impersonated_brand || 'unknown brand'}`);
            (v.flags || []).slice(0, 3).forEach(f => visFlags.push(f));
        });
        if (visFlags.length === 0) visFlags.push('No visual threats detected');
        setLayerCard(layers.visual, maxVisRisk, visFlags);
    } else {
        resetLayerCard(layers.visual);
    }

    // --- Layer 5: Links ---
    if (data.link_analysis) {
        const la = data.link_analysis;
        const linkFlags = [];
        linkFlags.push(`${la.total_links} links found, ${la.checked_links} checked, ${la.suspicious_links} suspicious`);
        (la.flags || []).slice(0, 4).forEach(f => linkFlags.push(f));
        setLayerCard(layers.links, la.risk_score, linkFlags);
    } else {
        resetLayerCard(layers.links);
    }

    // --- Risk Factors ---
    if (data.risk_factors && data.risk_factors.length > 0) {
        riskFactorsCard.style.display = 'block';
        riskFactorsList.innerHTML = data.risk_factors
            .map(f => `<li><span class="rf-icon">🔴</span> ${escapeHtml(f)}</li>`)
            .join('');
    } else {
        riskFactorsCard.style.display = 'none';
    }
}

// ---------- HTML Escape ----------
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ---------- Analyze ----------
async function analyze() {
    const text = emailInput.innerText.trim();
    if (!text) {
        showError('Please enter an email body to analyze.');
        emailInput.focus();
        return;
    }

    // Get the raw HTML from the contenteditable div (preserves <a href> links)
    const emailHtml = emailInput.innerHTML || null;

    // Set loading state
    analyzeBtn.classList.add('loading');
    analyzeBtn.disabled = true;
    resultsSection.classList.remove('visible');

    try {
        const body = {
            text,
            email_html: emailHtml,
            subject: subjectInput.value.trim() || null,
            crawl_urls: crawlToggle.checked,
            take_screenshots: screenshotToggle.checked,
        };

        const res = await fetch(`${API_BASE}/deep-analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({ detail: res.statusText }));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }

        const data = await res.json();
        renderResults(data);

    } catch (err) {
        showError(`Analysis failed: ${err.message}`);
        console.error('Deep-analyze error:', err);
    } finally {
        analyzeBtn.classList.remove('loading');
        analyzeBtn.disabled = false;
    }
}

// ---------- Event Listeners ----------
analyzeBtn.addEventListener('click', analyze);

// Screenshot toggle depends on crawl toggle
crawlToggle.addEventListener('change', () => {
    if (!crawlToggle.checked) {
        screenshotToggle.checked = false;
        screenshotToggle.disabled = true;
        screenshotToggle.parentElement.style.opacity = '0.4';
    } else {
        screenshotToggle.disabled = false;
        screenshotToggle.parentElement.style.opacity = '1';
    }
});

// Ctrl+Enter to submit
emailInput.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        analyze();
    }
});

// ---------- Init ----------
checkHealth();
// Re-check health every 30 seconds
setInterval(checkHealth, 30000);
