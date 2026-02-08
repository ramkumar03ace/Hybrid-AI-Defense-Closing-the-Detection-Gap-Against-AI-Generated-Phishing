# Processed Dataset - Improved for Real-World Generalization

## Dataset Overview

| Metric | Value |
|--------|-------|
| **Total Samples** | 5,819 |
| **Legitimate Emails** | 2,989 (51.4%) |
| **Phishing Emails** | 2,830 (48.6%) |
| **Number of Sources** | 7 |

---

## Data Sources

### Legitimate Emails (2,989 samples)

| Source | Count | Description |
|--------|-------|-------------|
| Enron | 1,499 | Real corporate emails (highly diverse) |
| SpamAssasin | 500 | Real personal/business emails |
| LLM-generated | 990 | AI-generated legitimate emails |

### Phishing Emails (2,830 samples)

| Source | Count | Description |
|--------|-------|-------------|
| LLM-generated | 1,000 | AI-generated phishing emails |
| Nazario | 499 | Classic phishing corpus |
| Nigerian_Fraud | 496 | 419 scam/advance-fee fraud |
| phishing_email | 500 | Mixed phishing styles |
| Human-generated | 335 | Original curated phishing |

---

## Train/Validation/Test Splits

| Split | Samples | Percentage |
|-------|---------|------------|
| Training | 4,655 | 80% |
| Validation | 582 | 10% |
| Test | 582 | 10% |

All splits are **stratified by label** to maintain class balance.

---

## Preprocessing Applied

1. **Text Cleaning**
   - HTML tag removal
   - URL anonymization → `[URL]`
   - Email anonymization → `[EMAIL]`
   - Special character handling
   - Whitespace normalization

2. **Quality Filters**
   - Minimum text length: 50 characters
   - Duplicate removal (by text content)

---

## Key Improvement: Diversity

**Previous Version (v1):**
- 4,000 samples from 2 sources (human + LLM)
- LLM emails were templated ("Dear X, I hope this finds you...")
- Poor generalization to real-world emails

**Current Version (v2):**
- 5,819 samples from 7 diverse sources
- Real corporate emails (Enron)
- Real phishing patterns (Nazario, Nigerian Fraud)
- Multiple email styles and formats
- **Expected: Better real-world generalization**

---

## Files

```
data/processed/
├── master_dataset.csv    # All 5,819 samples
├── train.csv             # 4,655 samples (80%)
├── validation.csv        # 582 samples (10%)
└── test.csv              # 582 samples (10%)
```

## Schema

| Column | Type | Description |
|--------|------|-------------|
| `text` | string | Cleaned email content |
| `label` | int | 0 = Legitimate, 1 = Phishing |
| `source` | string | Dataset origin |
| `email_type` | string | "legit" or "phishing" |

---

## Next Steps

1. Upload `train.csv`, `validation.csv`, `test.csv` to Google Colab
2. Retrain DistilBERT model with same hyperparameters
3. Test with arbitrary real-world emails
4. Verify improved generalization
