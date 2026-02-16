# 🧠 Model Documentation

## Current Model — V2

| Property | Value |
|----------|-------|
| Architecture | DistilBERT (66M params, 6 transformer layers) |
| Task | Binary classification — Phishing vs Legitimate |
| Accuracy | **99.17%** |
| Training Data | 9,600 samples (human + LLM generated) |
| Tokenizer | WordPiece (max 512 tokens) |
| Output | Confidence score (0–1) |

### V2 Scoring Weights (Updated)

| Layer | Weight | Notes |
|-------|--------|-------|
| Text (NLP) | 15% | Reduced — model struggles with edge cases |
| URL Intel | 30% | WHOIS, SSL, VirusTotal, patterns |
| Visual | 25% | Fake login / brand impersonation |
| Links | 20% | Redirect chains, domain changes |
| Reserved | 10% | For future CNN visual model |

**Multi-layer boost:** If 2+ layers flag suspicious → +0.15 added to combined score.

---

## Known Limitations (V2)

### 1. Misspelled / Typosquatted Phishing — NOT DETECTED

**Example that V2 classifies as LEGITIMATE (99.9% confidence):**
```
Subject: urgent! action needed
Body: ur bank is suspended. contant support@micr0soft.com for sloution or www.micr0soft.xyz
```

**Root cause:** DistilBERT uses WordPiece tokenization. Misspelled words get broken into subword tokens (`micr0soft` → `[mic, ##r, ##0, ##soft]`), but the model hasn't learned that unusual subword patterns = phishing.

**Why:** The training data contains mostly "clean" phishing text. AI-generated phishing (LLM dataset) has *perfect* grammar, so the model may have learned "bad grammar = legitimate casual email."

### 2. Short / Informal Emails

Brief, casual phishing attempts with slang or SMS-style language may bypass the model.

### 3. AI-Generated Phishing (Advanced)

Very well-crafted LLM-generated phishing that mimics corporate tone perfectly is hard to distinguish from legitimate email.

---

## V3 Improvement Plan

### Data Augmentation
- [ ] **Typo injection** — Randomly introduce spelling errors into existing phishing samples (character swap, substitution, deletion)
- [ ] **Homograph augmentation** — Replace characters with lookalikes (`o` → `0`, `l` → `1`, `a` → `@`)
- [ ] **Slang/informal augmentation** — Convert phishing samples to SMS-style language (`you` → `u`, `your` → `ur`)
- [ ] Target: **+2,000 augmented phishing samples**

### Feature Engineering (Pre-Model)
- [ ] **Spelling score** — Count misspellings and typo ratio per email
- [ ] **Urgency keyword detector** — Flag words like "urgent", "suspended", "verify", "immediately"
- [ ] **Combine:** High typo ratio + urgency keywords = strong phishing signal (even without ML)

### Model Architecture
- [ ] Fine-tune V3 on augmented dataset (9,600 original + 2,000 augmented = ~11,600 samples)
- [ ] Evaluate on dedicated test set of misspelled phishing emails
- [ ] Consider ensemble: DistilBERT text score + spelling-based heuristic score

### Scoring Weight Adjustment (Post V3)
- Once V3 model accuracy improves on edge cases, consider increasing text weight back to 25–30%
- Current 15% text weight is a temporary fix to let URL/Link layers compensate

---

## Model Versions History

| Version | Accuracy | Dataset | Key Change |
|---------|----------|---------|------------|
| V1 | 98.63% | Human-generated only | Baseline |
| V2 | 99.17% | Human + LLM generated | Added AI phishing samples |
| V3 | TBD | + Augmented (typos, homographs) | Fix misspelling blindspot |
