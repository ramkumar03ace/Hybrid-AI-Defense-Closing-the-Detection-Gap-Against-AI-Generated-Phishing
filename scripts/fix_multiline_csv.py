"""
Script to convert multi-line CSV files to single-line format.
Each email will be on a single row by replacing newlines within fields with spaces.
"""

import pandas as pd
import os

def fix_multiline_csv(input_path, output_path):
    """
    Read a CSV file where some fields span multiple lines,
    and save it with all newlines within fields replaced by spaces.
    """
    print(f"Processing: {input_path}")
    
    # Read the CSV file - pandas handles quoted multi-line fields properly
    df = pd.read_csv(input_path, encoding='utf-8', on_bad_lines='warn')
    
    print(f"  Original rows: {len(df)}")
    print(f"  Columns: {list(df.columns)}")
    
    # Replace newlines in all string columns with spaces
    for col in df.columns:
        if df[col].dtype == 'object':  # string columns
            df[col] = df[col].apply(lambda x: ' '.join(str(x).split()) if pd.notna(x) else x)
    
    # Save to new file - quoting ensures proper CSV format
    df.to_csv(output_path, index=False, encoding='utf-8')
    
    # Verify by counting lines
    with open(output_path, 'r', encoding='utf-8') as f:
        line_count = sum(1 for _ in f)
    
    print(f"  Output rows (including header): {line_count}")
    print(f"  Saved to: {output_path}")
    print()
    
    return df

def main():
    base_dir = r"d:\VIT\VIT Sem 8\Sem Project 2\Hybrid-AI-Defense-Closing-the-Detection-Gap-Against-AI-Generated-Phishing\data\raw\human-generated"
    
    # Files to process
    files = [
        ("legit.csv", "legit_fixed.csv"),
        ("phishing.csv", "phishing_fixed.csv")
    ]
    
    for input_file, output_file in files:
        input_path = os.path.join(base_dir, input_file)
        output_path = os.path.join(base_dir, output_file)
        
        try:
            fix_multiline_csv(input_path, output_path)
        except Exception as e:
            print(f"Error processing {input_file}: {e}")

if __name__ == "__main__":
    main()
