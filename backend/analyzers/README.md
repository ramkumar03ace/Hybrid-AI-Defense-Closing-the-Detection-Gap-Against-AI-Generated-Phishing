# Analyzers Module

This module handles URL analysis and email parsing for phishing detection.

---

## Architecture

```
analyzers/
├── __init__.py          # Module exports
├── email_parser.py      # Extract URLs, emails, metadata from text
├── url_analyzer.py      # Multi-layered URL phishing detection
└── README.md            # This file
```

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

print(parsed.urls)    # ['http://evil.tk/login']
print(parsed.sender)  # None
print(parsed.has_html) # False
```

---

### 2. URL Analyzer (`url_analyzer.py`)

Performs multi-layered analysis on each URL to detect phishing.

#### Layer 1: Pattern Detection (Local, Instant)

Checks URLs against known suspicious patterns:

| Check | What It Detects | Example |
|-------|-----------------|---------|
| IP-based URL | Domain is an IP address | `http://192.168.1.1/login` |
| Suspicious TLD | High-risk TLDs | `.tk`, `.ml`, `.xyz`, `.top` |
| Brand Impersonation | Known brand in wrong domain | `paypal-secure.tk` |
| Excessive Subdomains | Too many dots in domain | `login.secure.paypal.evil.com` |
| Long URLs | URL > 200 characters | Obfuscated redirect URLs |
| @ Symbol Trick | `@` used to mislead | `http://google.com@evil.com` |
| Homograph Attack | Number substitutions | `g00gle.com`, `paypa1.com` |
| No HTTPS | Insecure connection | `http://` instead of `https://` |

#### Layer 2: WHOIS Lookup (Domain Age)

Queries domain registration data:

| Domain Age | Risk Level | Reasoning |
|------------|------------|-----------|
| < 30 days | 🔴 High | Phishing domains are often newly registered |
| 30–180 days | 🟡 Medium | Still relatively new |
| > 180 days | 🟢 Low | Established domains are less likely phishing |

**Also extracts:** Registrar name

#### Layer 3: SSL Certificate Check

Validates HTTPS security:

| Check | What It Means |
|-------|---------------|
| Valid SSL | Certificate is trusted and not expired |
| Invalid SSL | Self-signed or expired certificate (🔴 suspicious) |
| Expiring Soon | Certificate expiring in < 7 days |
| No SSL | Cannot establish secure connection |

**Also extracts:** Issuer (e.g., Let's Encrypt, DigiCert)

#### Layer 4: VirusTotal Integration (Optional)

Checks URL against 70+ security vendors:

| Result | Meaning |
|--------|---------|
| `malicious > 0` | Flagged as malware/phishing by security vendors |
| `suspicious > 0` | Potentially harmful |
| `harmless` | No threats detected |

> **Setup:** Set `VIRUSTOTAL_API_KEY` in `backend/.env` to enable this layer.
> Get a free API key at https://www.virustotal.com/gui/join-us

---

## Risk Scoring

Each URL gets a combined risk score from **0.0** (safe) to **1.0** (phishing):

```
Risk Score = Pattern Score + Domain Age Score + SSL Score + VirusTotal Score
```

| Signal | Weight |
|--------|--------|
| Brand impersonation | +0.25 |
| Domain < 30 days old | +0.25 |
| IP address as domain | +0.20 |
| Invalid SSL | +0.20 |
| Suspicious TLD (.tk, .xyz) | +0.15 |
| @ symbol trick | +0.15 |
| Homograph attack | +0.15 |
| No HTTPS | +0.10 |
| Domain 30–180 days | +0.10 |
| Excessive subdomains | +0.10 |
| Long URL | +0.05 |
| VirusTotal malicious | +0.05 per vendor (max 0.30) |

**Verdict thresholds:**
- `risk_score < 0.30` → **Not suspicious**
- `risk_score >= 0.30` → **Suspicious**

---

## Full Analysis (Combined)

The `/api/v1/full-analyze` endpoint combines text + URL analysis:

```
Overall Risk = (Text Score × 0.60) + (URL Score × 0.40)
```

| Combined Score | Verdict |
|---------------|---------|
| ≥ 0.70 | 🔴 **PHISHING** |
| 0.35 – 0.69 | 🟡 **SUSPICIOUS** |
| < 0.35 | 🟢 **SAFE** |

---

## API Endpoints

### `POST /api/v1/analyze-url`

Analyze a single URL:

```json
// Request
{ "url": "http://secure-paypal-verify.tk/login" }

// Response
{
  "results": [{
    "url": "http://secure-paypal-verify.tk/login",
    "domain": "secure-paypal-verify.tk",
    "is_suspicious": true,
    "risk_score": 0.55,
    "flags": [
      "Suspicious TLD: .tk",
      "Possible brand impersonation: paypal",
      "Not using HTTPS"
    ],
    "domain_age_days": null,
    "ssl_valid": null,
    "vt_malicious": null
  }],
  "total_urls": 1,
  "suspicious_count": 1,
  "highest_risk": 0.55
}
```

### `POST /api/v1/full-analyze`

Combined text + URL analysis:

```json
// Request
{
  "text": "Your PayPal account is suspended. Verify at http://paypal-verify.tk/login",
  "subject": "Urgent: Account Suspended"
}

// Response
{
  "text_analysis": {
    "is_phishing": true,
    "confidence": 0.9981,
    "label": "PHISHING",
    "risk_level": "HIGH"
  },
  "urls_found": 1,
  "url_analysis": { ... },
  "overall_verdict": "PHISHING",
  "overall_risk_score": 0.82,
  "risk_factors": [
    "Email text classified as phishing (99.8% confidence)",
    "Suspicious TLD: .tk",
    "Possible brand impersonation: paypal"
  ]
}
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `python-whois` | WHOIS domain lookups |
| `requests` | VirusTotal API calls |
| `ssl` / `socket` | SSL certificate validation (built-in) |
| `re` | URL/email pattern matching (built-in) |
