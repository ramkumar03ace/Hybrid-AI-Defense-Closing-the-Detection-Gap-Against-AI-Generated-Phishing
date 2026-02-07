# Processed Data - Phishing Detection Dataset

## Overview

This folder contains the preprocessed and cleaned dataset for the AI Phishing Email Detector project, optimized for DistilBERT training.

---

## Files

| File | Rows | Description |
|------|------|-------------|
| `master_dataset.csv` | ~3198 | Complete cleaned dataset |
| `train.csv` | ~2558 (80%) | Training split |
| `validation.csv` | ~320 (10%) | Validation split |
| `test.csv` | ~320 (10%) | Test split |

---

## Schema

| Column | Type | Description |
|--------|------|-------------|
| `text` | string | Cleaned email content |
| `label` | int | 0 = Legitimate, 1 = Phishing |
| `source` | string | "human" or "llm" |
| `email_type` | string | "legit" or "phishing" |

---

## Data Sources

### Human-Generated Emails
- **Legitimate**: Real corporate emails (Enron, SpamAssassin)
- **Phishing**: Real phishing samples (Nazario Corpus, Kaggle)

### LLM-Generated Emails  
- **Legitimate**: AI-generated normal emails
- **Phishing**: AI-generated phishing emails (Novel contribution)

---

## Preprocessing Philosophy for DistilBERT

### Why Minimal Preprocessing?

DistilBERT uses a **WordPiece tokenizer** that already handles punctuation, numbers, and special characters. Aggressive preprocessing removes valuable phishing signals.

### What We KEEP ✅

| Element | Reason |
|---------|--------|
| **Numbers** | Phone/account numbers are phishing signals |
| **Brackets** | `[URGENT]`, `(Action Required)` are phishing patterns |
| **Special chars** | `$`, `!`, `@` create urgency signals |
| **Punctuation** | `!!!`, `???` indicate emotional manipulation |
| **Case** | `URGENT`, `CLICK NOW` patterns matter |

### What We REMOVE/TRANSFORM ❌

| Element | Action | Reason |
|---------|--------|--------|
| HTML tags | Remove | Noise for text model |
| Encoding artifacts | Remove | `Â`, `\xa0` are parsing errors |
| URLs | Replace with `[URL]` | Preserves "link exists" signal without memorizing domains |
| Email addresses | Replace with `[EMAIL]` | Anonymizes while keeping signal |
| Extra whitespace | Normalize | Multiple spaces add noise |
| Short texts | Remove | < 10 chars = no meaningful content |
| Duplicates | Remove | Prevents data leakage |

---

## Preprocessing Applied

1. ✅ Combined subject + body for human emails
2. ✅ Removed HTML tags
3. ✅ **URL Anonymization** → Replaced with `[URL]`
4. ✅ **Email Anonymization** → Replaced with `[EMAIL]`
5. ✅ Cleaned encoding artifacts (Â, \xa0, etc.)
6. ✅ Normalized whitespace
7. ✅ Removed entries with < 10 characters
8. ✅ Removed duplicate entries
9. ✅ Shuffled and split 80/10/10

---

## Usage

```python
import pandas as pd

# Load training data
train_df = pd.read_csv('data/processed/train.csv')

# For model training
X_train = train_df['text']
y_train = train_df['label']
```

---

*Generated on: February 7, 2026*
