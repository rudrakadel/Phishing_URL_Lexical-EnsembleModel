import pandas as pd
import numpy as np
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

def train():
    print("Training Tier 1 URL Model offline...")
    
    # Paths
    current_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(os.path.dirname(current_dir))
    dataset_candidates = [
        os.path.join(base_dir, "phishing_dataset_3.csv"),
        os.path.join(base_dir, "unnecessary", "phishing_dataset_3.csv"),
        os.path.join(base_dir, "unnecessary", "datasets", "phishing_dataset_3.csv"),
    ]
    dataset_path = next((path for path in dataset_candidates if os.path.exists(path)), None)
    if dataset_path is None:
        raise FileNotFoundError("Could not find phishing_dataset_3.csv in the project root or unnecessary datasets folder.")
    
    # Load dataset
    df = pd.read_csv(dataset_path)
    
    # Features & Target
    features = [
        "length_url", "length_hostname", "nb_dots", "nb_hyphens", "nb_www",
        "ratio_digits_url", "length_words_raw", "longest_words_raw",
        "longest_word_path", "phish_hints", "nb_slash", "shortest_word_host"
    ]
    
    # Standardize column mapping to make it robust
    df.columns = [c.strip().lower() for c in df.columns]
    features_lower = [f.lower() for f in features]
    
    target = "status"
    if target not in df.columns:
        # Try finding standard targets
        for col in ["label", "class", "target", "result"]:
            if col in df.columns:
                target = col
                break
                
    print(f"Target column detected: {target}")
    
    X = df[features_lower].copy()
    y = df[target].astype(str).str.strip().str.lower().map({
        "phishing": 1,
        "legitimate": 0,
        "1": 1,
        "0": 0
    }).astype(int)
    
    # Stratified Train/Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Preprocessor pipeline
    preprocessor = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )
    
    # Transform data
    X_train_scaled = preprocessor.fit_transform(X_train)
    X_test_scaled = preprocessor.transform(X_test)
    
    # Model: RandomForestClassifier
    model = RandomForestClassifier(
        n_estimators=250,
        max_depth=12,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train_scaled, y_train)
    
    # Predictions
    preds = model.predict(X_test_scaled)
    probs = model.predict_proba(X_test_scaled)[:, 1]
    
    # Metrics
    acc = accuracy_score(y_test, preds)
    f1 = f1_score(y_test, preds)
    auc = roc_auc_score(y_test, probs)
    
    print("\nModel Training Metrics:")
    print(f"  Accuracy: {acc:.2%}")
    print(f"  F1 Score: {f1:.2%}")
    print(f"  ROC-AUC : {auc:.2%}")
    
    # Save artifacts in the current folder (Model/1)
    current_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(current_dir, "tier1_url_model.pkl")
    preprocessor_path = os.path.join(current_dir, "preprocessor.pkl")
    
    joblib.dump(model, model_path)
    joblib.dump(preprocessor, preprocessor_path)
    
    print(f"\nTier 1 model successfully saved to: {model_path}")
    print(f"Tier 1 preprocessor successfully saved to: {preprocessor_path}")

if __name__ == "__main__":
    train()
