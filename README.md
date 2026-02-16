# 🛡️ Hybrid AI Defense — Closing the Detection Gap Against AI-Generated Phishing

> Multi-layer phishing detection system that combines NLP, URL intelligence, web crawling, and visual analysis

**Author:** Ramkumar  
**University:** VIT Vellore (B.Tech CSE)  
**Timeline:** 5 Weeks  
**Credits:** 5

---

## 📋 Project Overview

A comprehensive phishing detection system that goes beyond simple text analysis. This project uses multi-layer analysis including:

- **Email text analysis** (NLP with transformer models)
- **URL analysis** (reputation, domain age, SSL, patterns)
- **Website crawling** (actually visits and analyzes linked sites)
- **Visual analysis** (detects fake login pages, brand spoofing)
- **Recursive link checking** (follows redirect chains to catch hidden threats)

### 🎯 Unique Selling Point (Novelty)

Most phishing detectors catch traditional, human-written phishing emails. This project specifically targets **AI-generated phishing emails** — a growing threat as LLMs become more accessible.

---

## 🏗️ System Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     INCOMING EMAIL TEXT                       │
│         POST /api/v1/deep-analyze                            │
└────────────────────────┬─────────────────────────────────────┘
                         │
          ┌──────────────┼──────────────────┐
          ▼              ▼                  │
   ┌─────────────┐  ┌──────────────┐        │
   │ LAYER 1     │  │ EMAIL PARSER │        │
   │ DistilBERT  │  │ extract URLs │        │
   │ Text (35%)  │  │ extract meta │        │
   └──────┬──────┘  └──────┬───────┘        │
          │                │                │
          │                ▼                │
          │   ┌────────────────────────┐    │
          │   │ LAYER 2: URL ANALYZER  │    │
          │   │ (20% weight)           │    │
          │   │ • WHOIS domain age     │    │
          │   │ • SSL certificate      │    │
          │   │ • VirusTotal (70+ AVs) │    │
          │   │ • Pattern matching     │    │
          │   │ • Brand impersonation  │    │
          │   └────────────┬───────────┘    │
          │                │                │
          │                ▼                │
          │   ┌────────────────────────┐    │
          │   │ LAYER 3: WEB CRAWLER   │    │
          │   │ (Playwright + Process) │    │
          │   │ • Headless Chromium    │    │
          │   │ • Screenshot capture   │    │
          │   │ • Form/login detection │    │
          │   │ • Redirect tracking    │    │
          │   └────────────┬───────────┘    │
          │                │                │
          │                ▼                │
          │   ┌────────────────────────┐    │
          │   │ LAYER 4: VISUAL        │    │
          │   │ ANALYZER (25% weight)  │    │
          │   │ • Fake login detection │    │
          │   │ • Brand impersonation  │    │
          │   │   (12+ brands)         │    │
          │   │ • Credential harvesting│    │
          │   └────────────┬───────────┘    │
          │                │                │
          │                ▼                │
          │   ┌────────────────────────┐    │
          │   │ LAYER 5: LINK CHECKER  │    │
          │   │ (10% weight)           │    │
          │   │ • Follow redirects     │    │
          │   │ • Domain change detect │    │
          │   │ • URL shortener detect │    │
          │   └────────────┬───────────┘    │
          │                │                │
          ▼                ▼                ▼
   ┌───────────────────────────────────────────────┐
   │          WEIGHTED RISK AGGREGATOR             │
   │  Score = Text×0.15 + URL×0.30 + Visual×0.25  │
   │          + Links×0.20 + bonus                 │
   │  2+ layers flagged → +0.15 boost              │
   └───────────────────────┬───────────────────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │  ≥0.65 → 🔴 PHISHING │
                │  ≥0.30 → 🟡 SUSPICIOUS│
                │  <0.30 → 🟢 SAFE     │
                └─────────────────────┘
```

---

## 🔍 Component Details

| Layer | Component | Weight | What it checks | Technology |
|-------|-----------|--------|----------------|------------|
| 1 | `email_classifier.py` | 15% | Email text — urgency, threats, AI-generated patterns | DistilBERT (fine-tuned, 99.17%) |
| 2 | `url_analyzer.py` | 30% | Domain age, SSL, VirusTotal reputation, suspicious patterns | python-whois + ssl + VirusTotal API |
| 3 | `web_crawler.py` | — | Actually visits URLs in sandboxed browser, takes screenshots | Playwright Chromium (multiprocessing) |
| 4 | `visual_analyzer.py` | 25% | Detects fake login pages, brand impersonation (12+ brands) | Heuristic rules (CNN planned) |
| 5 | `link_checker.py` | 20% | Follows redirects, detects domain changes, URL shorteners | requests + redirect chain analysis |
| — | `deep_router.py` | — | Combines all 5 layers into weighted risk score | Weighted aggregation + boost logic |

---

## 📊 ML Model Details

### Architecture
- **Base Model:** DistilBERT (66M parameters, 6 transformer layers)
- **Type:** Fine-tuned binary text classification
- **Output:** Phishing vs Legitimate with confidence score (0–1)
- **Thresholds:** ≥0.85 = HIGH risk, ≥0.50 = MEDIUM risk

### Model Versions
| Version | Accuracy | Dataset | Notes |
|---------|----------|---------|-------|
| V1 | 98.63% | Human-generated only | Baseline |
| V2 | **99.17%** | Human + LLM generated | Current production model |

### Why DistilBERT?
- 40% smaller than BERT, 60% faster
- Retains 97% of BERT's performance
- Perfect for deployment (extension + web app)
- Understands context, not just keywords

---

## 📁 Dataset (V2)

### Training Data — 9,600 samples
| Source | Samples | Type |
|--------|---------|------|
| Enron Email Corpus | 2,993 | Legitimate |
| LLM-Generated | 1,990 | Phishing + Legitimate |
| Phishing Email Dataset | 1,500 | Phishing |
| SpamAssassin Corpus | 1,000 | Mixed |
| Nigerian Fraud | 995 | Phishing |
| Nazario Corpus | 991 | Phishing |
| Human-Generated | 131 | Mixed |

**Label Distribution:** 4,983 legitimate (0) • 4,617 phishing (1)

### Novel Contribution
- **AI-Generated Phishing Emails** — Custom LLM-generated dataset (1,990 samples)
- Multi-source dataset combining 7 different corpora
- Compares detection of human-written vs AI-written phishing
- Total: **9,600 samples** across all categories

---

## 🛠️ Tech Stack (100% FREE)

| Component | Technology | Status |
|-----------|------------|--------|
| NLP Model | HuggingFace DistilBERT (fine-tuned) | ✅ |
| Backend API | Python 3.12 + FastAPI + Uvicorn | ✅ |
| URL Intelligence | python-whois + ssl + VirusTotal API | ✅ |
| Web Crawling | Playwright Chromium (headless) | ✅ |
| Visual Detection | Heuristic rules (12+ brands) | ✅ |
| Link Analysis | requests + redirect chain tracking | ✅ |
| Frontend | HTML + CSS + JS (dark mode) | ✅ |
| Chrome Extension | Manifest V3 | ⬜ Planned |
| CNN Visual Model | ResNet/EfficientNet on screenshots | ⬜ Planned |

**Total Cost: ₹0**

---

## 📅 Timeline (5 Weeks)

### Week 1: Data & Model ✅
- [x] Download existing datasets (Nazario, Enron, SpamAssassin)
- [x] Generate AI phishing samples using LLM
- [x] Preprocess and clean all data
- [x] Fine-tune DistilBERT — V1 (98.63%), V2 (99.17%)
- [x] Evaluate and tune model performance

### Week 2: Backend & URL Analysis ✅
- [x] Set up FastAPI backend
- [x] Implement email parsing (extract text, URLs, headers)
- [x] Build URL analyzer (WHOIS, SSL, VirusTotal integration)
- [x] Create API endpoints (`/analyze`, `/analyze-url`, `/full-analyze`)
- [x] Basic testing

### Week 3: Web Crawler & Visual Analysis ✅
- [x] Set up Playwright for safe web crawling (multiprocessing for Windows)
- [x] Implement screenshot capture (saved in `backend/screenshots/`)
- [x] Build visual analyzer (fake login detection for 12+ brands)
- [x] Implement recursive link checker (redirects, URL shorteners)
- [x] Integrate all into `/deep-analyze` endpoint (5-layer pipeline)

### Week 4: Frontend & Polish 🔄 ← YOU ARE HERE
- [x] Build web app UI (dashboard to paste & analyze emails)
- [ ] Create Chrome extension (Gmail integration)
- [x] Connect everything to backend
- [x] Rebalance scoring weights (Text 35%→15%, URL 20%→30%, Links 10%→20%)
- [x] Testing and bug fixes

### Week 5: CNN Visual Model & Final Integration ⬜
- [ ] Collect screenshot dataset (phishing vs real login pages)
- [ ] Train CNN model (ResNet/EfficientNet) on page screenshots
- [ ] Replace heuristic visual analyzer with CNN-based detection
- [ ] Integrate CNN predictions into `/deep-analyze` risk scoring
- [ ] Final testing, documentation, and paper prep

- [ ] Documentation & presentation prep
---

## 📂 Project Structure

```
Hybrid-AI-Defense/
├── README.md
├── requirements.txt
│
├── data/
│   ├── raw/                    # Original datasets
│   │   ├── human-generated/    # Human phishing + legit emails
│   │   └── llm-generated/      # AI-generated phishing + legit
│   └── processed/              # Cleaned data
│
├── backend/
│   ├── main.py                 # FastAPI app
│   ├── config.py               # Settings (API keys, thresholds)
│   ├── analyzers/
│   │   ├── email_parser.py     # URL/email extraction from text
│   │   ├── url_analyzer.py     # WHOIS + SSL + VirusTotal + patterns
│   │   ├── web_crawler.py      # Playwright crawler (subprocess)
│   │   ├── crawl_worker.py     # Isolated crawl process
│   │   ├── visual_analyzer.py  # Fake login page detection
│   │   └── link_checker.py     # Recursive redirect analysis
│   ├── routers/
│   │   ├── email_router.py     # /analyze endpoint
│   │   ├── url_router.py       # /analyze-url, /full-analyze
│   │   └── deep_router.py      # /deep-analyze (5-layer)
│   ├── services/
│   │   └── email_classifier.py # DistilBERT model service
│   ├── models/
│   │   └── schemas.py          # Pydantic request/response schemas
│   └── screenshots/            # Crawled page screenshots
│
├── frontend/                   # (Week 4)
│   ├── index.html
│   ├── styles.css
│   └── app.js
│
├── extension/                  # (Week 4)
│   ├── manifest.json
│   ├── popup.html
│   └── popup.js
│
└── notebooks/
    └── training.ipynb          # Colab notebook for training
```

---

## 🎯 Deliverables

1. **ML Model** — Fine-tuned DistilBERT for phishing detection ✅
2. **Backend API** — FastAPI service with all analyzers ✅
3. **Web Application** — Dark mode dashboard with 5-layer results ✅
4. **Chrome Extension** — Gmail integration for real-time scanning ⬜
5. **CNN Visual Model** — Screenshot-based fake login detection ⬜
6. **Documentation** — Full project documentation ⬜
7. **Paper (Optional)** — Research paper for publication ⬜

---

## 📄 Paper Potential

### Possible Venues
- ICCCNT (International Conference on Computing, Communication and Networking Technologies)
- ICACCS (International Conference on Advanced Computing and Communication Systems)
- IJERT / IRJET (Indian Journals)

### Novel Contributions
1. Custom dataset of AI-generated phishing emails
2. Multi-modal detection system (text + URL + visual)
3. CNN-based fake login page detection from screenshots
4. Recursive redirect chain analysis
5. Focus on LLM-generated threats

---

## 🚀 Quick Start

```bash
# Clone the repo
git clone <repo-url>

# Set up virtual environment
python -m venv .venv
.venv\Scripts\activate       # Windows

# Install dependencies
cd backend
pip install -r requirements.txt
playwright install chromium

# Run backend
uvicorn main:app --reload --port 8001

# API docs available at:
# http://localhost:8001/docs
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/analyze` | ML text classification only |
| POST | `/api/v1/analyze-url` | URL static analysis (WHOIS, SSL, VT) |
| POST | `/api/v1/full-analyze` | Text + URL analysis combined |
| POST | `/api/v1/deep-analyze` | **Full 5-layer pipeline** (text + URL + crawl + visual + links) |
| GET | `/api/v1/health` | Health check |

---

*Last Updated: February 16, 2026 — Scoring weights rebalanced, frontend dashboard completed*
