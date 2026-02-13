# Analyzers Module

This module handles all phishing detection analysis layers — URL checks, web crawling, visual fake login detection, and link checking.

---

## Architecture

```
analyzers/
├── __init__.py            # Module exports
├── email_parser.py        # Extract URLs, emails, metadata from text
├── url_analyzer.py        # URL static analysis (WHOIS, SSL, VirusTotal)
├── web_crawler.py         # Playwright headless browser + screenshots
├── visual_analyzer.py     # Fake login page detection (12+ brands)
├── link_checker.py        # Recursive redirect & link analysis
└── README.md              # This file
```

---

## API Endpoints — What's the Difference?

| Endpoint | Input | Layers Used | Speed | Use Case |
|----------|-------|-------------|-------|----------|
| `POST /analyze` | Email text | ML text only | ⚡ ~100ms | Quick text check |
| `POST /analyze-url` | Single URL | WHOIS + SSL + VT + patterns | ⚡ ~2s | Check a specific URL |
| `POST /full-analyze` | Email text | ML text + URL analysis | 🔄 ~3s | Text + URL (no browser) |
| `POST /deep-analyze` | Email text | **All 5 layers** | 🐢 ~10s | Full investigation |

### When to use which?

- **`/analyze`** — Just want to know if email text is phishing (fastest)
- **`/analyze-url`** — Have a suspicious URL, want to check domain age, SSL, VirusTotal
- **`/full-analyze`** — Want ML + URL checks together but **no browser crawling** (lighter, faster)
- **`/deep-analyze`** — Want **everything**: ML + URL + visit the page + detect fake logins + check all links (most thorough, slowest)

---

## Components

### 1. Email Parser (`email_parser.py`)

Extracts structured data from raw email text.

| Feature | Description |
|---------|-------------|
| **URL Extraction** | Finds all `http://` and `https://` URLs, plus bare `www.` domains |
| **Email Extraction** | Detects sender email addresses |
| **HTML Detection** | Checks if email contains HTML tags |
| **Subject Parsing** | Extracts URLs from subject lines too |

**Usage:**
```python
from analyzers.email_parser import EmailParser

parsed = EmailParser.parse(
    text="Click http://evil.tk/login to verify",
    subject="Urgent Alert"
)

print(parsed.urls)     # ['http://evil.tk/login']
print(parsed.sender)   # None
print(parsed.has_html)  # False
```

---

### 2. URL Analyzer (`url_analyzer.py`)

Static URL analysis — no browser needed.

#### Layer 1: Pattern Detection (Instant)

| Check | What It Detects | Example |
|-------|-----------------|---------|
| IP-based URL | Domain is an IP address | `http://192.168.1.1/login` |
| Suspicious TLD | High-risk TLDs | `.tk`, `.ml`, `.xyz`, `.top` |
| Brand Impersonation | Known brand in wrong domain | `paypal-secure.tk` |
| Excessive Subdomains | Too many dots | `login.secure.paypal.evil.com` |
| Long URLs | URL > 200 characters | Obfuscated redirect URLs |
| @ Symbol Trick | `@` used to mislead | `http://google.com@evil.com` |
| Homograph Attack | Number substitutions | `g00gle.com`, `paypa1.com` |
| No HTTPS | Insecure connection | `http://` instead of `https://` |

#### Layer 2: WHOIS Lookup (Domain Age)

| Domain Age | Risk Level | Reasoning |
|------------|------------|-----------|
| < 30 days | 🔴 High | Phishing domains are often newly registered |
| 30–180 days | 🟡 Medium | Still relatively new |
| > 180 days | 🟢 Low | Established domains are less likely phishing |

#### Layer 3: SSL Certificate Check

| Check | What It Means |
|-------|---------------|
| Valid SSL | Certificate is trusted and not expired |
| Invalid SSL | Self-signed or expired (🔴 suspicious) |
| Expiring Soon | Certificate expiring in < 7 days |
| No SSL | Cannot establish secure connection |

#### Layer 4: VirusTotal Integration (Optional)

Checks URL against 70+ security vendors.

> **Setup:** Set `VIRUSTOTAL_API_KEY` in `backend/.env` to enable.

---

### 3. Web Crawler (`web_crawler.py`)

Visits URLs in a **sandboxed Playwright Chromium browser**.

| Feature | Description |
|---------|-------------|
| **Headless browsing** | Chrome runs invisibly, no GUI needed |
| **Screenshot capture** | Takes PNG screenshot of visited page |
| **Form detection** | Finds login forms, password fields, input names |
| **Redirect tracking** | Records full redirect chain |
| **Content extraction** | Extracts page title, text, external links |
| **Safety controls** | Sandbox mode, timeout limits, no extensions |

Screenshots saved in: `backend/screenshots/`

---

### 4. Visual Analyzer (`visual_analyzer.py`)

Detects **fake login pages** by analyzing crawled page content.

**Supported brands (12+):** Google, Microsoft, Apple, PayPal, Amazon, Facebook, Netflix, LinkedIn, Instagram, Twitter/X, Chase, Wells Fargo

| Check | What It Detects |
|-------|-----------------|
| Brand impersonation | Page mentions "PayPal" but hosted on `evil.tk` |
| Credential harvesting | Multiple password/email/username input fields |
| Cross-domain forms | Form submits data to a different domain |
| Urgency language | "verify within 24 hours", "account suspended" |
| Sensitive data requests | SSN, credit card, CVV fields |
| Redirect tricks | Domain changes during redirect chain |

---

### 5. Link Checker (`link_checker.py`)

Follows links recursively to detect suspicious redirect patterns.

| Check | What It Detects |
|-------|-----------------|
| Domain change | Redirect goes to a different domain |
| Excessive redirects | More than 3 hops in chain |
| URL shorteners | bit.ly, tinyurl.com, etc. |
| Suspicious destination | Final URL has `.tk`, `.xyz` TLD |
| Protocol downgrade | HTTPS → HTTP during redirect |
| Connection timeout | Server doesn't respond (possible malicious) |

---

## Risk Scoring

### URL Analysis Score (0.0 – 1.0)

| Signal | Weight |
|--------|--------|
| Brand impersonation | +0.25 |
| Domain < 30 days old | +0.25 |
| IP address as domain | +0.20 |
| Invalid SSL | +0.20 |
| Suspicious TLD | +0.15 |
| @ symbol trick | +0.15 |
| Homograph attack | +0.15 |
| No HTTPS | +0.10 |
| VirusTotal malicious | +0.05 per vendor (max 0.30) |

### Full Analysis Score

```
Overall Risk = (Text Score × 0.60) + (URL Score × 0.40)
```

### Deep Analysis Score (5-layer weighted)

```
Overall Risk = (Text × 0.35) + (URL × 0.20) + (Visual × 0.25) + (Links × 0.10) + bonus
```

If 3+ layers flag it → **+0.15 boost**

| Combined Score | Verdict |
|---------------|---------|
| ≥ 0.65 | 🔴 **PHISHING** |
| 0.30 – 0.64 | 🟡 **SUSPICIOUS** |
| < 0.30 | 🟢 **SAFE** |

---

## Example: Deep Analysis (Real Test)

```json
// Request
POST /api/v1/deep-analyze
{
  "text": "hi this is mircosoft, login at https://www.microsoft.xyz",
  "subject": "hi from mircosft",
  "crawl_urls": true,
  "take_screenshots": true
}

// Response
{
  "text_analysis": {
    "is_phishing": false,
    "confidence": 0.9983,
    "label": "LEGITIMATE",
    "risk_level": "LOW"
  },
  "urls_found": 2,
  "url_analysis": {
    "results": [
      {
        "url": "https://www.microsoft.xyz",
        "domain": "www.microsoft.xyz",
        "is_suspicious": true,
        "risk_score": 0.6,
        "flags": [
          "Suspicious TLD: .xyz",
          "Possible brand impersonation: microsoft",
          "Invalid SSL certificate"
        ],
        "domain_age_days": 4286,
        "registrar": "MarkMonitor, Inc.",
        "ssl_valid": false,
        "vt_malicious": 0
      }
    ],
    "suspicious_count": 2,
    "highest_risk": 0.7
  },
  "link_analysis": {
    "total_links": 2,
    "checked_links": 2,
    "suspicious_links": 2,
    "risk_score": 0.6,
    "flags": [
      "Redirect changes domain: www.microsoft.xyz → www.microsoft.com"
    ]
  },
  "overall_verdict": "SAFE",
  "overall_risk_score": 0.2006,
  "risk_factors": [
    "Suspicious TLD: .xyz",
    "Possible brand impersonation: microsoft",
    "Redirect changes domain: www.microsoft.xyz → www.microsoft.com"
  ],
  "analysis_layers": [
    "text_classification",
    "url_analysis",
    "web_crawling",
    "visual_analysis",
    "link_checking"
  ]
}
```

### What each layer detected:

| Layer | Finding |
|-------|---------|
| **Text (ML)** | Classified as LEGITIMATE (99.8%) — simple text fooled the model |
| **URL Analysis** | Flagged `.xyz` TLD, brand impersonation, invalid SSL |
| **Web Crawler** | Page didn't load (no content behind microsoft.xyz) |
| **Visual** | No fake login detected (page was empty) |
| **Link Checker** | Redirect to real `microsoft.com` detected |
| **Verdict** | SAFE (0.20) — text score pulled it down despite URL flags |

> **Note:** This shows why multi-layer analysis matters. The text alone missed
> the phishing, but URL analysis caught the `.xyz` impersonation. A more
> sophisticated phishing email with convincing text would trigger the text
> layer too, resulting in a PHISHING verdict.
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `python-whois` | WHOIS domain lookups |
| `requests` | VirusTotal API & link checking |
| `playwright` | Headless browser crawling |
| `ssl` / `socket` | SSL certificate validation (built-in) |
| `re` | URL/email pattern matching (built-in) |
