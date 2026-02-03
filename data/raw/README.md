# Raw Datasets - OpenClaw Phishing Detection

This directory contains all raw email datasets used for training the phishing detection model.

## 📊 Dataset Overview

| Dataset | Rows | Size (MB) | Content Type | Label Distribution |
|---------|------|-----------|--------------|-------------------|
| **Enron.csv** | 720,454 | 43.45 | Legitimate corporate emails | All legitimate (label=0) |
| **Nazario.csv** | 4,807 | 7.45 | Phishing emails | All phishing (label=1) |
| **SpamAssasin.csv** | 162,163 | 14.19 | Spam and Ham mixed | Mixed (label=0/1) |
| **Nigerian_Fraud.csv** | 117,113 | 8.77 | 419 scam/advance-fee fraud | All phishing (label=1) |
| **phishing_email.csv** | 82,486 | 101.67 | Phishing + Legitimate mix | Mixed (label=0/1) |

**Total Dataset Size**: ~1.08 million emails | ~175.53 MB

---

## 📋 Dataset Descriptions

### 1. Enron.csv
- **Source**: Enron Email Dataset
- **Content**: Real corporate emails from Enron Corporation
- **Use Case**: Provides examples of legitimate business communication
- **Columns**: `sender`, `receiver`, `date`, `subject`, `body`, `label`
- **Notes**: Largest source of legitimate emails for training

### 2. Nazario.csv
- **Source**: Nazario Phishing Corpus
- **Content**: Classic phishing email samples
- **Use Case**: Traditional phishing attack patterns
- **Columns**: `sender`, `receiver`, `date`, `subject`, `body`, `urls`, `label`
- **Notes**: Small but valuable collection of real phishing attempts

### 3. SpamAssasin.csv
- **Source**: SpamAssassin Public Corpus
- **Content**: Mix of spam and legitimate emails (ham)
- **Use Case**: General spam detection and legitimate email classification
- **Columns**: `sender`, `receiver`, `date`, `subject`, `body`, `label`, `urls`
- **Notes**: Well-balanced dataset for spam/ham classification

### 4. Nigerian_Fraud.csv
- **Source**: 419 Scam Email Collection
- **Content**: Nigerian advance-fee fraud emails
- **Use Case**: Specific type of social engineering phishing
- **Columns**: `sender`, `receiver`, `date`, `subject`, `body`, `urls`, `label`
- **Notes**: Contains unique linguistic patterns characteristic of 419 scams

### 5. phishing_email.csv
- **Source**: Mixed Phishing Email Dataset
- **Content**: Combination of phishing attempts and legitimate emails
- **Use Case**: Diverse phishing patterns including energy/utility company emails
- **Columns**: `text_combined`, `label`
- **Notes**: Large file size; contains varied email types

---

## 🎯 Label Convention

All datasets follow this labeling scheme:
- **`0`** = Legitimate email (ham)
- **`1`** = Phishing/Spam/Fraudulent email

---

## 📈 Estimated Distribution

Based on analysis:
- **Legitimate Emails**: ~803,000 (74%)
- **Phishing/Spam/Fraud**: ~280,000 (26%)

**Note**: The dataset is imbalanced toward legitimate emails. Balancing techniques (undersampling, oversampling, or SMOTE) should be considered during training.

---

## ✅ Recommendations

1. **Keep All Datasets**: Each provides unique value and diversity
2. **Preprocess Consistently**: 
   - Standardize column names across datasets
   - Ensure uniform label encoding
   - Handle missing values
   - Remove duplicates across datasets
3. **Balance During Training**: Use techniques like:
   - Class weights
   - SMOTE (Synthetic Minority Over-sampling)
   - Undersampling majority class
4. **Split Strategy**: Use stratified splitting to maintain class proportions

---

## 🔄 Next Steps

1. Combine all datasets into a unified preprocessing pipeline
2. Generate AI-generated phishing samples (500-1000 emails)
3. Clean and normalize all text data
4. Create train/validation/test splits (70/15/15)
5. Fine-tune DistilBERT model on combined dataset

---

## 📝 Notes

- **Last Updated**: February 3, 2026
- **Total Storage**: ~175 MB
- **Preprocessing Status**: Raw (not yet processed)
- **License**: Check individual dataset licenses before commercial use
