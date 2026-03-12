import pandas as pd #for data manipulation
from sklearn.model_selection import train_test_split
from heuristics import extract_features
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib




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

X = feature_df  # your 35 features
y = df['type']  # your labels (0 or 1)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)


joblib.dump(model, 'model.pkl')

print(f"Training samples: {len(X_train)}")
print(f"Testing samples: {len(X_test)}")
print("Model trained successfully! ✅")
print(f"Accuracy: {accuracy * 100:.2f}%")
