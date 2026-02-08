"""
Data Preprocessing Script for Phishing Detection
Combines and cleans all raw datasets into a master dataset
VERSION 2: Expanded data sources for better real-world generalization
"""

import pandas as pd
import re
import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"
PROCESSED_DIR = BASE_DIR / "data" / "processed"

# Ensure processed directory exists
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# CONFIGURATION - Adjust sample counts here
# ============================================================
CONFIG = {
    # Legitimate email sources
    "enron_legit_count": 1500,        # From Enron.csv
    "spamassasin_legit_count": 500,   # Ham from SpamAssasin.csv
    "llm_legit_count": 1000,          # From llm-generated/legit.csv
    "human_legit_count": 0,           # Original human legit (optional)
    
    # Phishing email sources
    "nazario_phishing_count": 500,    # From Nazario.csv
    "nigerian_phishing_count": 500,   # From Nigerian_Fraud.csv
    "phishing_email_count": 500,      # From phishing_email.csv
    "llm_phishing_count": 1000,       # From llm-generated/phishing.csv
    "human_phishing_count": 1000,     # Original human phishing
    
    # Random seed for reproducibility
    "random_seed": 42,
}


def clean_text(text):
    """Clean email text content"""
    if pd.isna(text) or text is None:
        return ""
    
    text = str(text)
    
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    
    # URL Anonymization - Replace URLs with [URL] placeholder
    text = re.sub(r'http[s]?://\S+', '[URL]', text)
    text = re.sub(r'www\.\S+', '[URL]', text)
    # Email anonymization
    text = re.sub(r'\S+@\S+\.\S+', '[EMAIL]', text)
    
    # Remove special characters and encoding issues
    text = text.replace('\xa0', ' ')
    text = text.replace('Â', '')
    text = text.replace('\r\n', ' ')
    text = text.replace('\n', ' ')
    text = text.replace('\r', ' ')
    text = text.replace('\t', ' ')
    
    # Remove multiple spaces
    text = re.sub(r'\s+', ' ', text)
    
    # Strip leading/trailing whitespace
    text = text.strip()
    
    return text


def load_enron_emails(count):
    """Load legitimate corporate emails from Enron dataset"""
    print(f"Loading Enron emails (target: {count})...")
    
    enron_path = RAW_DIR / "Enron.csv"
    if not enron_path.exists():
        print(f"  ⚠️ Enron.csv not found, skipping")
        return pd.DataFrame(columns=['text', 'label', 'source', 'email_type'])
    
    # Read in chunks to handle large file
    try:
        df = pd.read_csv(enron_path, usecols=['subject', 'body', 'label'], nrows=50000)
        
        # Combine subject and body
        df['text'] = df['subject'].fillna('') + ' ' + df['body'].fillna('')
        df['label'] = 0  # All legitimate
        df['source'] = 'enron'
        df['email_type'] = 'legit'
        
        # Clean and filter
        df['text'] = df['text'].apply(clean_text)
        df = df[df['text'].str.len() > 50]  # Minimum length
        
        # Random sample
        if len(df) > count:
            df = df.sample(n=count, random_state=CONFIG['random_seed'])
        
        print(f"  ✅ Loaded {len(df)} Enron emails")
        return df[['text', 'label', 'source', 'email_type']]
    
    except Exception as e:
        print(f"  ❌ Error loading Enron: {e}")
        return pd.DataFrame(columns=['text', 'label', 'source', 'email_type'])


def load_spamassasin_ham(count):
    """Load legitimate (ham) emails from SpamAssasin dataset"""
    print(f"Loading SpamAssasin ham emails (target: {count})...")
    
    spam_path = RAW_DIR / "SpamAssasin.csv"
    if not spam_path.exists():
        print(f"  ⚠️ SpamAssasin.csv not found, skipping")
        return pd.DataFrame(columns=['text', 'label', 'source', 'email_type'])
    
    try:
        df = pd.read_csv(spam_path)
        
        # Filter only ham (legitimate) emails - label = 0
        df = df[df['label'] == 0]
        
        # Combine subject and body
        if 'subject' in df.columns and 'body' in df.columns:
            df['text'] = df['subject'].fillna('') + ' ' + df['body'].fillna('')
        elif 'text' in df.columns:
            pass  # Already has text column
        else:
            df['text'] = df['body'].fillna('')
        
        df['label'] = 0
        df['source'] = 'spamassasin'
        df['email_type'] = 'legit'
        
        # Clean and filter
        df['text'] = df['text'].apply(clean_text)
        df = df[df['text'].str.len() > 50]
        
        # Random sample
        if len(df) > count:
            df = df.sample(n=count, random_state=CONFIG['random_seed'])
        
        print(f"  ✅ Loaded {len(df)} SpamAssasin ham emails")
        return df[['text', 'label', 'source', 'email_type']]
    
    except Exception as e:
        print(f"  ❌ Error loading SpamAssasin: {e}")
        return pd.DataFrame(columns=['text', 'label', 'source', 'email_type'])


def load_nazario_phishing(count):
    """Load phishing emails from Nazario corpus"""
    print(f"Loading Nazario phishing emails (target: {count})...")
    
    nazario_path = RAW_DIR / "Nazario.csv"
    if not nazario_path.exists():
        print(f"  ⚠️ Nazario.csv not found, skipping")
        return pd.DataFrame(columns=['text', 'label', 'source', 'email_type'])
    
    try:
        df = pd.read_csv(nazario_path)
        
        # Combine subject and body
        if 'subject' in df.columns and 'body' in df.columns:
            df['text'] = df['subject'].fillna('') + ' ' + df['body'].fillna('')
        elif 'text' in df.columns:
            pass
        else:
            df['text'] = df['body'].fillna('')
        
        df['label'] = 1  # All phishing
        df['source'] = 'nazario'
        df['email_type'] = 'phishing'
        
        # Clean and filter
        df['text'] = df['text'].apply(clean_text)
        df = df[df['text'].str.len() > 50]
        
        # Random sample
        if len(df) > count:
            df = df.sample(n=count, random_state=CONFIG['random_seed'])
        
        print(f"  ✅ Loaded {len(df)} Nazario phishing emails")
        return df[['text', 'label', 'source', 'email_type']]
    
    except Exception as e:
        print(f"  ❌ Error loading Nazario: {e}")
        return pd.DataFrame(columns=['text', 'label', 'source', 'email_type'])


def load_nigerian_fraud(count):
    """Load 419 scam emails from Nigerian Fraud dataset"""
    print(f"Loading Nigerian Fraud emails (target: {count})...")
    
    fraud_path = RAW_DIR / "Nigerian_Fraud.csv"
    if not fraud_path.exists():
        print(f"  ⚠️ Nigerian_Fraud.csv not found, skipping")
        return pd.DataFrame(columns=['text', 'label', 'source', 'email_type'])
    
    try:
        df = pd.read_csv(fraud_path)
        
        # Combine subject and body
        if 'subject' in df.columns and 'body' in df.columns:
            df['text'] = df['subject'].fillna('') + ' ' + df['body'].fillna('')
        elif 'text' in df.columns:
            pass
        else:
            df['text'] = df['body'].fillna('')
        
        df['label'] = 1  # All phishing/fraud
        df['source'] = 'nigerian_fraud'
        df['email_type'] = 'phishing'
        
        # Clean and filter
        df['text'] = df['text'].apply(clean_text)
        df = df[df['text'].str.len() > 50]
        
        # Random sample
        if len(df) > count:
            df = df.sample(n=count, random_state=CONFIG['random_seed'])
        
        print(f"  ✅ Loaded {len(df)} Nigerian Fraud emails")
        return df[['text', 'label', 'source', 'email_type']]
    
    except Exception as e:
        print(f"  ❌ Error loading Nigerian Fraud: {e}")
        return pd.DataFrame(columns=['text', 'label', 'source', 'email_type'])


def load_phishing_email_dataset(count):
    """Load phishing samples from phishing_email.csv"""
    print(f"Loading phishing_email.csv phishing samples (target: {count})...")
    
    phishing_path = RAW_DIR / "phishing_email.csv"
    if not phishing_path.exists():
        print(f"  ⚠️ phishing_email.csv not found, skipping")
        return pd.DataFrame(columns=['text', 'label', 'source', 'email_type'])
    
    try:
        # Read first chunk to avoid memory issues
        df = pd.read_csv(phishing_path, nrows=20000)
        
        # Filter phishing only (label = 1)
        df = df[df['label'] == 1]
        
        # Use text_combined if available
        if 'text_combined' in df.columns:
            df['text'] = df['text_combined']
        elif 'text' not in df.columns:
            df['text'] = df.get('body', '')
        
        df['label'] = 1
        df['source'] = 'phishing_email'
        df['email_type'] = 'phishing'
        
        # Clean and filter
        df['text'] = df['text'].apply(clean_text)
        df = df[df['text'].str.len() > 50]
        
        # Random sample
        if len(df) > count:
            df = df.sample(n=count, random_state=CONFIG['random_seed'])
        
        print(f"  ✅ Loaded {len(df)} phishing_email.csv samples")
        return df[['text', 'label', 'source', 'email_type']]
    
    except Exception as e:
        print(f"  ❌ Error loading phishing_email: {e}")
        return pd.DataFrame(columns=['text', 'label', 'source', 'email_type'])


def load_llm_generated():
    """Load and process LLM-generated datasets"""
    print("Loading LLM-generated datasets...")
    
    dfs = []
    
    # Load legit emails
    if CONFIG['llm_legit_count'] > 0:
        legit_path = RAW_DIR / "llm-generated" / "legit_fixed.csv"
        if legit_path.exists():
            legit_df = pd.read_csv(legit_path)
            legit_df['label'] = 0
            legit_df['source'] = 'llm'
            legit_df['email_type'] = 'legit'
            
            if len(legit_df) > CONFIG['llm_legit_count']:
                legit_df = legit_df.sample(n=CONFIG['llm_legit_count'], random_state=CONFIG['random_seed'])
            
            print(f"  ✅ Loaded {len(legit_df)} LLM legitimate emails")
            dfs.append(legit_df[['text', 'label', 'source', 'email_type']])
    
    # Load phishing emails
    if CONFIG['llm_phishing_count'] > 0:
        phishing_path = RAW_DIR / "llm-generated" / "phishing_fixed.csv"
        if phishing_path.exists():
            phishing_df = pd.read_csv(phishing_path)
            phishing_df['label'] = 1
            phishing_df['source'] = 'llm'
            phishing_df['email_type'] = 'phishing'
            
            if len(phishing_df) > CONFIG['llm_phishing_count']:
                phishing_df = phishing_df.sample(n=CONFIG['llm_phishing_count'], random_state=CONFIG['random_seed'])
            
            print(f"  ✅ Loaded {len(phishing_df)} LLM phishing emails")
            dfs.append(phishing_df[['text', 'label', 'source', 'email_type']])
    
    if dfs:
        return pd.concat(dfs, ignore_index=True)
    return pd.DataFrame(columns=['text', 'label', 'source', 'email_type'])


def load_human_phishing():
    """Load original human phishing dataset"""
    print(f"Loading original human phishing (target: {CONFIG['human_phishing_count']})...")
    
    if CONFIG['human_phishing_count'] == 0:
        return pd.DataFrame(columns=['text', 'label', 'source', 'email_type'])
    
    phishing_path = RAW_DIR / "human-generated" / "phishing_fixed.csv"
    if not phishing_path.exists():
        print(f"  ⚠️ Human phishing file not found")
        return pd.DataFrame(columns=['text', 'label', 'source', 'email_type'])
    
    try:
        df = pd.read_csv(phishing_path)
        df['text'] = df['subject'].fillna('') + ' ' + df['body'].fillna('')
        df['label'] = 1
        df['source'] = 'human'
        df['email_type'] = 'phishing'
        
        if len(df) > CONFIG['human_phishing_count']:
            df = df.sample(n=CONFIG['human_phishing_count'], random_state=CONFIG['random_seed'])
        
        print(f"  ✅ Loaded {len(df)} human phishing emails")
        return df[['text', 'label', 'source', 'email_type']]
    
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return pd.DataFrame(columns=['text', 'label', 'source', 'email_type'])


def main():
    print("=" * 60)
    print("PHISHING DETECTION - DATA PREPROCESSING v2")
    print("Expanded Data Sources for Better Generalization")
    print("=" * 60)
    
    # Load all datasets
    datasets = []
    
    # LEGITIMATE EMAILS
    print("\n" + "-" * 40)
    print("LOADING LEGITIMATE EMAILS")
    print("-" * 40)
    
    datasets.append(load_enron_emails(CONFIG['enron_legit_count']))
    datasets.append(load_spamassasin_ham(CONFIG['spamassasin_legit_count']))
    
    # PHISHING EMAILS
    print("\n" + "-" * 40)
    print("LOADING PHISHING EMAILS")
    print("-" * 40)
    
    datasets.append(load_nazario_phishing(CONFIG['nazario_phishing_count']))
    datasets.append(load_nigerian_fraud(CONFIG['nigerian_phishing_count']))
    datasets.append(load_phishing_email_dataset(CONFIG['phishing_email_count']))
    datasets.append(load_human_phishing())
    
    # LLM GENERATED
    print("\n" + "-" * 40)
    print("LOADING LLM-GENERATED EMAILS")
    print("-" * 40)
    
    datasets.append(load_llm_generated())
    
    # Combine all data
    print("\n" + "=" * 60)
    print("COMBINING DATASETS")
    print("=" * 60)
    
    master_df = pd.concat(datasets, ignore_index=True)
    print(f"Total samples before cleaning: {len(master_df)}")
    
    # Clean text (LLM already cleaned during load)
    print("\nCleaning text...")
    master_df['text'] = master_df['text'].apply(clean_text)
    
    # Remove empty texts
    before_count = len(master_df)
    master_df = master_df[master_df['text'].str.len() > 50]
    print(f"Removed {before_count - len(master_df)} empty/short entries")
    
    # Remove duplicates
    before_count = len(master_df)
    master_df = master_df.drop_duplicates(subset=['text'], keep='first')
    print(f"Removed {before_count - len(master_df)} duplicate entries")
    
    # Final dataset stats
    print("\n" + "=" * 60)
    print("FINAL DATASET STATISTICS")
    print("=" * 60)
    print(f"Total samples: {len(master_df)}")
    print("\nBy Label:")
    print(master_df['label'].value_counts().to_string())
    print("\nBy Source:")
    print(master_df['source'].value_counts().to_string())
    print("\nCross-tabulation (Source x Label):")
    print(pd.crosstab(master_df['source'], master_df['label']))
    
    # Save master dataset
    output_path = PROCESSED_DIR / "master_dataset.csv"
    master_df.to_csv(output_path, index=False)
    print(f"\n✅ Saved master dataset to: {output_path}")
    
    # Create train/val/test splits (stratified manually)
    print("\nCreating stratified train/validation/test splits (80/10/10)...")
    
    # Manual stratified split
    def stratified_split(df, train_ratio=0.8, val_ratio=0.1, seed=42):
        """Manual stratified split by label"""
        train_dfs = []
        val_dfs = []
        test_dfs = []
        
        for label in df['label'].unique():
            label_df = df[df['label'] == label].sample(frac=1, random_state=seed).reset_index(drop=True)
            n = len(label_df)
            train_end = int(train_ratio * n)
            val_end = int((train_ratio + val_ratio) * n)
            
            train_dfs.append(label_df[:train_end])
            val_dfs.append(label_df[train_end:val_end])
            test_dfs.append(label_df[val_end:])
        
        return (
            pd.concat(train_dfs, ignore_index=True).sample(frac=1, random_state=seed),
            pd.concat(val_dfs, ignore_index=True).sample(frac=1, random_state=seed),
            pd.concat(test_dfs, ignore_index=True).sample(frac=1, random_state=seed)
        )
    
    train_df, val_df, test_df = stratified_split(master_df, seed=CONFIG['random_seed'])
    
    # Save splits
    train_df.to_csv(PROCESSED_DIR / "train.csv", index=False)
    val_df.to_csv(PROCESSED_DIR / "validation.csv", index=False)
    test_df.to_csv(PROCESSED_DIR / "test.csv", index=False)
    
    print(f"  - train.csv: {len(train_df)} samples")
    print(f"  - validation.csv: {len(val_df)} samples")
    print(f"  - test.csv: {len(test_df)} samples")
    
    # Class balance in splits
    print("\nClass balance in splits:")
    print(f"  Train: {train_df['label'].value_counts().to_dict()}")
    print(f"  Val:   {val_df['label'].value_counts().to_dict()}")
    print(f"  Test:  {test_df['label'].value_counts().to_dict()}")
    
    print("\n✅ Preprocessing complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
