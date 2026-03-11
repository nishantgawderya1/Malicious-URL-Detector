import pandas as pd #for data manipulation
from heuristics import extract_features

# Load the dataset
df = pd.read_csv('malicious_phish.csv')

#convert type to binary: 0 for benign, 1 for phishing/defacement/malware
df['type'] = df['type'].map({ 
    'benign': 0,
    'phishing': 1,
    'defacement': 1,
    'malware': 1
})

# Display basic info about the dataset
print(df.head())
print(f"\nShape: {df.shape}")
print(f"Columns: {list(df.columns)}")

print(df['type'].value_counts())

# Extract features for every URL
feature_df = pd.DataFrame(df['url'].apply(extract_features).tolist())
print(feature_df.head())