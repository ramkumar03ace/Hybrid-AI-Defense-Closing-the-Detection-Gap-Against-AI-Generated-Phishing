# Processed Dataset V2 - 10K Balanced Dataset

## Overview

| Metric | Value |
|--------|-------|
| **Total Samples** | 9,600 |
| **Legitimate Emails** | 4,983 (51.9%) |
| **Phishing Emails** | 4,617 (48.1%) |
| **Number of Sources** | 7 |

---

## Data Sources

### Legitimate Emails (4,983 samples)

| Source | Count |
|--------|-------|
| Enron | 2,993 |
| SpamAssasin | 1,000 |
| LLM-generated | 990 |

### Phishing Emails (4,617 samples)

| Source | Count |
|--------|-------|
| phishing_email | 1,500 |
| LLM-generated | 1,000 |
| Nazario | 991 |
| Nigerian_Fraud | 995 |
| Human-generated | 131 |

---

## Train/Validation/Test Splits

| Split | Samples |
|-------|---------|
| Training | 7,679 |
| Validation | 960 |
| Test | 960 |

---

## Files

```
data/processed_v2/
├── master_dataset.csv    # All 9,600 samples
├── train.csv             # 7,679 samples (80%)
├── validation.csv        # 960 samples (10%)
└── test.csv              # 960 samples (10%)
```

## Usage

Upload `train.csv`, `validation.csv`, `test.csv` to Google Colab and run `notebooks/training_v2.ipynb`.
