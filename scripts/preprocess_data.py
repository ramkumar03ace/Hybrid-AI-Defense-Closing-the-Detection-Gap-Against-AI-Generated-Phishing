"""
Data Preprocessing Script for Phishing Detection
Combines and cleans all raw datasets into a master dataset
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


def clean_text(text):
    """Clean email text content"""
    if pd.isna(text) or text is None:
        return ""
    
    text = str(text)
    
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    
    # URL Anonymization - Replace URLs with [URL] placeholder
    # This preserves the "link exists" signal without memorizing specific domains
    text = re.sub(r'http[s]?://\S+', '[URL]', text)
    text = re.sub(r'www\.\S+', '[URL]', text)
    # Also catch email-style links
    text = re.sub(r'\S+@\S+\.\S+', '[EMAIL]', text)
    
    # Remove special characters and encoding issues
    text = text.replace('\xa0', ' ')  # Non-breaking space
    text = text.replace('Â', '')       # Common encoding artifact
    text = text.replace('\r\n', ' ')   # Windows line endings
    text = text.replace('\n', ' ')     # Unix line endings
    text = text.replace('\r', ' ')     # Old Mac line endings
    text = text.replace('\t', ' ')     # Tabs
    
    # Remove multiple spaces
    text = re.sub(r'\s+', ' ', text)
    
    # Strip leading/trailing whitespace
    text = text.strip()
    
    return text


def load_human_generated():
    """Load and process human-generated datasets"""
    print("Loading human-generated datasets...")
    
    # Load legit emails
    legit_path = RAW_DIR / "human-generated" / "legit_fixed.csv"
    legit_df = pd.read_csv(legit_path)
    
    # Combine subject and body for text
    legit_df['text'] = legit_df['subject'].fillna('') + ' ' + legit_df['body'].fillna('')
    legit_df['label'] = 0  # Legit = 0
    legit_df['source'] = 'human'
    legit_df['email_type'] = 'legit'
    
    print(f"  - Loaded {len(legit_df)} legitimate emails")
    
    # Load phishing emails
    phishing_path = RAW_DIR / "human-generated" / "phishing_fixed.csv"
    phishing_df = pd.read_csv(phishing_path)
    
    # Combine subject and body for text
    phishing_df['text'] = phishing_df['subject'].fillna('') + ' ' + phishing_df['body'].fillna('')
    phishing_df['label'] = 1  # Phishing = 1
    phishing_df['source'] = 'human'
    phishing_df['email_type'] = 'phishing'
    
    print(f"  - Loaded {len(phishing_df)} phishing emails")
    
    # Combine and select columns
    human_df = pd.concat([legit_df, phishing_df], ignore_index=True)
    human_df = human_df[['text', 'label', 'source', 'email_type']]
    
    return human_df


def load_llm_generated():
    """Load and process LLM-generated datasets"""
    print("Loading LLM-generated datasets...")
    
    # Load legit emails
    legit_path = RAW_DIR / "llm-generated" / "legit_fixed.csv"
    legit_df = pd.read_csv(legit_path)
    legit_df['label'] = 0  # Legit = 0
    legit_df['source'] = 'llm'
    legit_df['email_type'] = 'legit'
    
    print(f"  - Loaded {len(legit_df)} legitimate emails")
    
    # Load phishing emails
    phishing_path = RAW_DIR / "llm-generated" / "phishing_fixed.csv"
    phishing_df = pd.read_csv(phishing_path)
    phishing_df['label'] = 1  # Phishing = 1
    phishing_df['source'] = 'llm'
    phishing_df['email_type'] = 'phishing'
    
    print(f"  - Loaded {len(phishing_df)} phishing emails")
    
    # Combine and select columns
    llm_df = pd.concat([legit_df, phishing_df], ignore_index=True)
    llm_df = llm_df[['text', 'label', 'source', 'email_type']]
    
    return llm_df


def main():
    print("=" * 60)
    print("PHISHING DETECTION - DATA PREPROCESSING")
    print("=" * 60)
    
    # Load all datasets
    human_df = load_human_generated()
    llm_df = load_llm_generated()
    
    # Combine all data
    print("\nCombining datasets...")
    master_df = pd.concat([human_df, llm_df], ignore_index=True)
    print(f"Total samples before cleaning: {len(master_df)}")
    
    # Clean text
    print("\nCleaning text...")
    master_df['text'] = master_df['text'].apply(clean_text)
    
    # Remove empty texts
    before_count = len(master_df)
    master_df = master_df[master_df['text'].str.len() > 10]  # Minimum 10 chars
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
    print("\nBy Email Type:")
    print(master_df['email_type'].value_counts().to_string())
    print("\nCross-tabulation (Source x Label):")
    print(pd.crosstab(master_df['source'], master_df['email_type']))
    
    # Save master dataset
    output_path = PROCESSED_DIR / "master_dataset.csv"
    master_df.to_csv(output_path, index=False)
    print(f"\n✅ Saved master dataset to: {output_path}")
    print(f"   Rows: {len(master_df)}, Columns: {list(master_df.columns)}")
    
    # Create train/val/test splits
    print("\nCreating train/validation/test splits (80/10/10)...")
    
    # Shuffle the data
    master_df = master_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Calculate split sizes
    total = len(master_df)
    train_size = int(0.8 * total)
    val_size = int(0.1 * total)
    
    train_df = master_df[:train_size]
    val_df = master_df[train_size:train_size + val_size]
    test_df = master_df[train_size + val_size:]
    
    # Save splits
    train_df.to_csv(PROCESSED_DIR / "train.csv", index=False)
    val_df.to_csv(PROCESSED_DIR / "validation.csv", index=False)
    test_df.to_csv(PROCESSED_DIR / "test.csv", index=False)
    
    print(f"  - train.csv: {len(train_df)} samples")
    print(f"  - validation.csv: {len(val_df)} samples")
    print(f"  - test.csv: {len(test_df)} samples")
    
    print("\n✅ Preprocessing complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
