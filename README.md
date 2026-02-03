# 🛡️ AI Phishing Email Detector

> Multi-layer phishing detection system with focus on AI-generated phishing emails

**Author:** Ramkumar  
**University:** VIT Vellore (B.Tech CSE)  
**Timeline:** 1 Month  
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
┌─────────────────────────────────────────────────────────┐
│                    INCOMING EMAIL                        │
└────────────────────────┬────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
   ┌──────────┐   ┌────────────┐   ┌──────────┐
   │  TEXT    │   │    URL     │   │ HEADER   │
   │ ANALYZER │   │  EXTRACTOR │   │ ANALYZER │
   │ (BERT)   │   │            │   │(metadata)│
   └────┬─────┘   └─────┬──────┘   └────┬─────┘
        │               │               │
        │               ▼               │
        │    ┌─────────────────────┐    │
        │    │   URL ANALYZER      │    │
        │    │ • Domain age        │    │
        │    │ • SSL certificate   │    │
        │    │ • Reputation check  │    │
        │    │ • Pattern matching  │    │
        │    └──────────┬──────────┘    │
        │               │               │
        │               ▼               │
        │    ┌─────────────────────┐    │
        │    │   WEB CRAWLER       │    │
        │    │ (Sandboxed browser) │    │
        │    │ • Visit actual site │    │
        │    │ • Screenshot it     │    │
        │    │ • Extract all links │    │
        │    └──────────┬──────────┘    │
        │               │               │
        │               ▼               │
        │    ┌─────────────────────┐    │
        │    │  VISUAL ANALYZER    │    │
        │    │ • Fake login page?  │    │
        │    │ • Brand spoofing?   │    │
        │    │ • Suspicious forms? │    │
        │    └──────────┬──────────┘    │
        │               │               │
        │               ▼               │
        │    ┌─────────────────────┐    │
        │    │  RECURSIVE LINK     │    │
        │    │     CHECKER         │    │
        │    │ (depth limit: 2-3)  │    │
        │    └──────────┬──────────┘    │
        │               │               │
        ▼               ▼               ▼
   ┌──────────────────────────────────────────┐
   │         FINAL RISK AGGREGATOR            │
   │   Combines all signals → Risk Score      │
   └──────────────────────────────────────────┘
                         │
                         ▼
              ⚠️ PHISHING: 87% confidence
              • Email text: suspicious urgency
              • URL: domain registered 2 days ago
              • Website: fake Google login page
              • Hidden redirect to: malware.ru
```

---

## 🔍 Component Details

| Layer | What it checks | Technology |
|-------|----------------|------------|
| Text Analyzer | Email body — urgency, threats, grammar, AI-generated patterns | DistilBERT (fine-tuned) |
| URL Analyzer | Domain reputation, age, SSL, typosquatting | VirusTotal API + WHOIS + Rules |
| Web Crawler | Actually visits site safely in sandbox | Playwright (headless browser) |
| Visual Analyzer | Screenshots → detects fake login pages | CNN or template matching |
| Link Crawler | Follows links on page, detects redirects | Recursive crawler with depth limit |
| Aggregator | Weights all signals → final verdict | Ensemble model / weighted rules |

---

## 📊 ML Model Details

### Architecture
- **Base Model:** DistilBERT (66M parameters, 6 transformer layers)
- **Type:** Fine-tuned text classification
- **Output:** Binary classification (Phishing vs Legitimate) with confidence score

### Why DistilBERT?
- 40% smaller than BERT, 60% faster
- Retains 97% of BERT's performance
- Perfect for deployment (extension + web app)
- Understands context, not just keywords

### Expected Accuracy
- Traditional phishing: **95-98%**
- AI-generated phishing: **90-95%**

---

## 📁 Dataset Strategy

### Existing Datasets (FREE)
| Dataset | Description | Use |
|---------|-------------|-----|
| Nazario Phishing Corpus | Real phishing emails | Phishing samples |
| Enron Email Dataset | Legitimate corporate emails | Negative samples |
| SpamAssassin Public Corpus | Spam vs Ham | Mixed samples |
| Kaggle Phishing Datasets | Various collections | Additional samples |

### Custom Dataset (OUR CONTRIBUTION)
- **AI-Generated Phishing Emails** — Created using free LLMs
- This is a **novel contribution** — no public dataset exists for this
- Target: 500-1000 AI-generated phishing samples

### Final Dataset Composition
```
Training Data
├── Legitimate emails: ~5000 samples
├── Traditional phishing: ~3000 samples
└── AI-generated phishing: ~1000 samples (NOVEL)
```

---

## 🛠️ Tech Stack (100% FREE)

| Component | Technology | Cost |
|-----------|------------|------|
| ML Training | Google Colab / Kaggle | FREE |
| NLP Model | HuggingFace DistilBERT | FREE |
| URL Reputation | VirusTotal API (500 req/day) | FREE |
| Domain Info | python-whois library | FREE |
| Web Crawling | Playwright | FREE |
| Backend | Python + FastAPI | FREE |
| Frontend | React / HTML+JS | FREE |
| Extension | Chrome Manifest V3 | FREE |
| Backend Hosting | Render / Railway | FREE tier |
| Frontend Hosting | Vercel / Netlify | FREE |
| Database | SQLite / Supabase | FREE |

**Total Cost: ₹0**

---

## 📅 Timeline (4 Weeks)

### Week 1: Data & Model
- [ ] Download existing datasets (Nazario, Enron, SpamAssassin)
- [ ] Generate AI phishing samples using LLM
- [ ] Preprocess and clean all data
- [ ] Fine-tune DistilBERT on combined dataset
- [ ] Evaluate and tune model performance

### Week 2: Backend & URL Analysis
- [ ] Set up FastAPI backend
- [ ] Implement email parsing (extract text, URLs, headers)
- [ ] Build URL analyzer (WHOIS, SSL, VirusTotal integration)
- [ ] Create API endpoints
- [ ] Basic testing

### Week 3: Web Crawler & Visual Analysis
- [ ] Set up Playwright for safe web crawling
- [ ] Implement screenshot capture
- [ ] Build visual analyzer (fake login detection)
- [ ] Implement recursive link checker
- [ ] Integrate all components

### Week 4: Frontend & Polish
- [ ] Build web app UI
- [ ] Create Chrome extension
- [ ] Connect everything to backend
- [ ] Testing and bug fixes
- [ ] Documentation
- [ ] Prepare presentation

---

## 📂 Project Structure

```
ai-phishing-detector/
├── README.md
├── requirements.txt
│
├── data/
│   ├── raw/                    # Original datasets
│   ├── processed/              # Cleaned data
│   └── ai_generated/           # Our custom AI phishing samples
│
├── model/
│   ├── train.py                # Training script
│   ├── evaluate.py             # Evaluation metrics
│   └── saved_models/           # Trained model files
│
├── backend/
│   ├── main.py                 # FastAPI app
│   ├── analyzers/
│   │   ├── text_analyzer.py    # BERT-based text analysis
│   │   ├── url_analyzer.py     # URL reputation & checks
│   │   ├── web_crawler.py      # Playwright crawler
│   │   ├── visual_analyzer.py  # Screenshot analysis
│   │   └── aggregator.py       # Final risk scoring
│   └── utils/
│
├── frontend/
│   ├── index.html
│   ├── styles.css
│   └── app.js
│
├── extension/
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   └── background.js
│
├── notebooks/
│   └── training.ipynb          # Colab notebook for training
│
└── docs/
    ├── architecture.md
    └── api.md
```

---

## 🎯 Deliverables

1. **ML Model** — Fine-tuned DistilBERT for phishing detection
2. **Backend API** — FastAPI service with all analyzers
3. **Web Application** — UI to paste and analyze emails
4. **Chrome Extension** — Gmail integration for real-time scanning
5. **Documentation** — Full project documentation
6. **Paper (Optional)** — Research paper for publication

---

## 📄 Paper Potential

### Possible Venues
- ICCCNT (International Conference on Computing, Communication and Networking Technologies)
- ICACCS (International Conference on Advanced Computing and Communication Systems)
- IJERT / IRJET (Indian Journals)

### Novel Contributions
1. Custom dataset of AI-generated phishing emails
2. Multi-modal detection system (text + URL + visual)
3. Recursive redirect chain analysis
4. Focus on LLM-generated threats

---

## 🚀 Quick Start (Coming Soon)

```bash
# Clone the repo
git clone <repo-url>

# Install dependencies
pip install -r requirements.txt

# Run backend
cd backend
uvicorn main:app --reload

# Run frontend
cd frontend
# Open index.html in browser
```

---

## 📞 Support

Built with the help of OC 🔥

---

*Last Updated: February 3, 2026*
