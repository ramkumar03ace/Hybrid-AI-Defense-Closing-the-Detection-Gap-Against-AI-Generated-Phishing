"""
Fix the LLM-generated phishing.csv to properly quote text fields
like in the legit.csv file.
"""
import csv
import os

def fix_phishing_csv():
    data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'raw', 'llm-generated')
    input_file = os.path.join(data_dir, 'phishing.csv')
    output_file = os.path.join(data_dir, 'phishing_fixed.csv')
    
    rows = []
    
    # Read the file line by line and parse it
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # First line is header
    header = lines[0].strip()
    
    # Process each line (except header)
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        
        # The format is: text,label where text may contain commas
        # The label is always at the end after the last comma
        # Find the last comma followed by the label (0 or 1)
        if line.endswith(',0'):
            text = line[:-2]
            label = '0'
        elif line.endswith(',1'):
            text = line[:-2]
            label = '1'
        else:
            print(f"Warning: Unexpected line format: {line[:100]}...")
            continue
        
        rows.append((text, label))
    
    # Write with proper CSV formatting (quoted text)
    with open(output_file, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, quoting=csv.QUOTE_NONNUMERIC)
        writer.writerow(['text', 'label'])
        for text, label in rows:
            writer.writerow([text, int(label)])
    
    print(f"Processed {len(rows)} rows from phishing.csv")
    print(f"Saved to: {output_file}")

if __name__ == '__main__':
    fix_phishing_csv()
