/* ============================================
   Hybrid AI Defense — Extension Popup Logic
   Connects to backend /deep-analyze endpoint
   ============================================ */

const API_BASE = 'http://localhost:8001/api/v1';

// ---------- DOM Refs ----------
const $ = (sel) => document.querySelector(sel);
const statusChip = $('#statusChip');
const extractBtn = $('#extractBtn');
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

// Store email HTML separately (textarea only holds plain text)
let storedEmailHtml = null;

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
        const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
        const data = await res.json();
        if (data.model_loaded) {
            statusChip.textContent = '● API Online';
            statusChip.className = 'status-chip online';
        } else {
            statusChip.textContent = '● API Degraded';
            statusChip.className = 'status-chip offline';
        }
    } catch {
        statusChip.textContent = '● API Offline';
        statusChip.className = 'status-chip offline';
    }
}

// ---------- Toast ----------
let toastTimer;
function showError(msg) {
    errorToast.textContent = msg;
    errorToast.classList.add('visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => errorToast.classList.remove('visible'), 4000);
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
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 40;

function setGauge(score, verdict) {
    const offset = GAUGE_CIRCUMFERENCE * (1 - score);
    gaugeFill.style.strokeDashoffset = offset;
    gaugeFill.style.stroke = verdictHex(verdict);
    animateNumber(gaugeScore, score);
}

function animateNumber(el, target) {
    const duration = 800;
    const start = performance.now();
    function tick(now) {
        const progress = Math.min((now - start) / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 3);
        el.textContent = (target * ease * 100).toFixed(0) + '%';
        if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
}

// ---------- Layer Card Helpers ----------
function setLayerCard(layerRef, score, flagsArr) {
    const cls = scoreColorClass(score);
    layerRef.score.textContent = (score * 100).toFixed(0) + '%';
    layerRef.score.className = `layer-score score-${cls}`;
    layerRef.bar.className = `layer-bar__fill bar-${cls}`;
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
    layerRef.score.className = 'layer-score';
    layerRef.bar.style.width = '0';
    layerRef.bar.className = 'layer-bar__fill';
    layerRef.flags.innerHTML = '<li style="color:var(--text-muted);opacity:0.5;">No data</li>';
}

// ---------- Render Results ----------
function renderResults(data) {
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

    // Layer 1: Text
    const textConf = data.text_analysis.confidence;
    const textRisk = data.text_analysis.is_phishing ? textConf : (1 - textConf);
    const textFlags = [
        `Label: ${data.text_analysis.label}`,
        `Confidence: ${(textConf * 100).toFixed(1)}%`,
        `Risk: ${data.text_analysis.risk_level}`,
    ];
    setLayerCard(layers.text, textRisk, textFlags);

    // Layer 2: URL
    if (data.url_analysis && data.url_analysis.results.length > 0) {
        const urlFlags = [];
        urlFlags.push(`${data.url_analysis.total_urls} URL(s), ${data.url_analysis.suspicious_count} suspicious`);
        data.url_analysis.results.forEach(r => {
            if (r.flags && r.flags.length > 0) {
                r.flags.slice(0, 2).forEach(f => urlFlags.push(f));
            }
        });
        setLayerCard(layers.url, data.url_analysis.highest_risk, urlFlags);
    } else {
        resetLayerCard(layers.url);
    }

    // Layer 3: Crawl
    if (data.crawl_results && data.crawl_results.length > 0) {
        const crawlFlags = [];
        let maxCrawlRisk = 0;
        data.crawl_results.forEach(c => {
            if (c.error) {
                crawlFlags.push(`❌ ${c.error}`);
            } else {
                crawlFlags.push(`${c.page_title || 'Untitled'}`);
                if (c.has_login_form) { crawlFlags.push('⚠️ Login form'); maxCrawlRisk = Math.max(maxCrawlRisk, 0.5); }
                if (c.has_password_field) { crawlFlags.push('⚠️ Password field'); maxCrawlRisk = Math.max(maxCrawlRisk, 0.6); }
                if (c.was_redirected) { crawlFlags.push(`↪ Redirected (${c.redirect_chain.length} hops)`); maxCrawlRisk = Math.max(maxCrawlRisk, 0.3); }
            }
        });
        setLayerCard(layers.crawl, maxCrawlRisk, crawlFlags);
    } else {
        resetLayerCard(layers.crawl);
    }

    // Layer 4: Visual
    if (data.visual_analysis && data.visual_analysis.length > 0) {
        const maxVisRisk = Math.max(...data.visual_analysis.map(v => v.risk_score));
        const visFlags = [];
        data.visual_analysis.forEach(v => {
            if (v.is_fake_login) visFlags.push(`🚨 Fake login — ${v.impersonated_brand || 'unknown'}`);
            (v.flags || []).slice(0, 2).forEach(f => visFlags.push(f));
        });
        if (visFlags.length === 0) visFlags.push('No visual threats');
        setLayerCard(layers.visual, maxVisRisk, visFlags);
    } else {
        resetLayerCard(layers.visual);
    }

    // Layer 5: Links
    if (data.link_analysis) {
        const la = data.link_analysis;
        const linkFlags = [];
        linkFlags.push(`${la.total_links} links, ${la.suspicious_links} suspicious`);
        (la.flags || []).slice(0, 3).forEach(f => linkFlags.push(f));
        setLayerCard(layers.links, la.risk_score, linkFlags);
    } else {
        resetLayerCard(layers.links);
    }

    // Risk Factors
    if (data.risk_factors && data.risk_factors.length > 0) {
        riskFactorsCard.style.display = 'block';
        riskFactorsList.innerHTML = data.risk_factors
            .map(f => `<li><span class="rf-icon">🔴</span> ${escapeHtml(f)}</li>`)
            .join('');
    } else {
        riskFactorsCard.style.display = 'none';
    }
}

// ---------- Escape HTML ----------
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ---------- Extract from Gmail ----------
async function extractFromGmail() {
    extractBtn.disabled = true;

    try {
        // Get the active tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (!tab || !tab.url || !tab.url.includes('mail.google.com')) {
            extractBtn.classList.add('error');
            extractBtn.querySelector('.btn-icon').textContent = '❌';
            showError('Please open Gmail first!');
            setTimeout(() => {
                extractBtn.classList.remove('error');
                extractBtn.querySelector('.btn-icon').textContent = '📧';
            }, 2000);
            return;
        }

        // Inject content script if not already loaded
        try {
            await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                files: ['content.js'],
            });
        } catch {
            // Content script might already be injected
        }

        // Send message to content script
        const response = await chrome.tabs.sendMessage(tab.id, { action: 'extract_email' });

        if (response && response.success) {
            emailInput.value = response.body;
            storedEmailHtml = response.body_html || null;
            if (response.subject) {
                subjectInput.value = response.subject;
            }
            extractBtn.classList.add('success');
            extractBtn.querySelector('.btn-icon').textContent = '✅';
            setTimeout(() => {
                extractBtn.classList.remove('success');
                extractBtn.querySelector('.btn-icon').textContent = '📧';
            }, 2000);
        } else {
            showError(response?.error || 'Could not extract email. Open an email first.');
            extractBtn.classList.add('error');
            extractBtn.querySelector('.btn-icon').textContent = '❌';
            setTimeout(() => {
                extractBtn.classList.remove('error');
                extractBtn.querySelector('.btn-icon').textContent = '📧';
            }, 2000);
        }
    } catch (err) {
        showError('Extraction failed. Make sure you have an email open in Gmail.');
        console.error('Extract error:', err);
    } finally {
        extractBtn.disabled = false;
    }
}

// ---------- Analyze ----------
async function analyze() {
    const text = emailInput.value.trim();
    if (!text) {
        showError('Please enter or extract an email to scan.');
        emailInput.focus();
        return;
    }

    analyzeBtn.classList.add('loading');
    analyzeBtn.disabled = true;
    resultsSection.classList.remove('visible');

    try {
        const body = {
            text,
            email_html: storedEmailHtml || null,
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
extractBtn.addEventListener('click', extractFromGmail);
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

emailInput.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        analyze();
    }
});

// Capture HTML from clipboard paste
emailInput.addEventListener('paste', (e) => {
    const html = e.clipboardData?.getData('text/html');
    if (html) {
        storedEmailHtml = html;
    }
});

// Clear stored HTML if user manually types
emailInput.addEventListener('input', () => {
    // Only clear if not from paste (paste fires input too, but after our paste handler)
    if (!storedEmailHtml) return;
});

// ---------- Init ----------
checkHealth();
