"""
Train Random Forest Model for Ransomware Detection
Trains on MalwareData.csv and saves model + scaler artifacts
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import joblib
import os
from pathlib import Path

# Create models directory if not exists
Path("models").mkdir(exist_ok=True)

def train_model():
    """Train Random Forest model on malware dataset"""
    
    print("[*] Loading dataset...")
    df = pd.read_csv("MalwareData.csv", sep="|")
    print(f"[+] Dataset shape: {df.shape}")
    
    # Drop non-feature columns
    print("[*] Preprocessing data...")
    df.drop(columns=["Name", "md5"], inplace=True, errors='ignore')
    
    # Separate features and labels
    X = df.drop(columns=["legitimate"])
    y = df["legitimate"]
    
    print(f"[+] Features: {X.shape[1]} | Samples: {X.shape[0]}")
    print(f"[+] Class distribution - Benign: {(y==1).sum()}, Malware: {(y==0).sum()}")
    
    # Scale features
    print("[*] Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Train-test split
    print("[*] Splitting data (70% train, 30% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.3, stratify=y, random_state=42
    )
    
    # Train Random Forest
    print("[*] Training Random Forest model...")
    rf_model = RandomForestClassifier(
        n_estimators=300,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features='log2',
        bootstrap=True,
        class_weight='balanced_subsample',
        n_jobs=-1,
        random_state=42,
        verbose=1
    )
    
    rf_model.fit(X_train, y_train)
    print("[+] Model training complete!")
    
    # Evaluate
    print("\n[*] Evaluating model...")
    y_pred = rf_model.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    
    print("\n" + "="*60)
    print("MODEL PERFORMANCE METRICS")
    print("="*60)
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print("="*60)
    print(f"\nConfusion Matrix:")
    print(cm)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Malware', 'Benign']))
    
    # Save model and scaler
    print("\n[*] Saving model and scaler...")
    joblib.dump(rf_model, "models/ransomware_model.pkl")
    joblib.dump(scaler, "models/scaler.pkl")
    
    print("[+] Model saved to: models/ransomware_model.pkl")
    print("[+] Scaler saved to: models/scaler.pkl")
    print("\n[✓] Training complete!")

if __name__ == "__main__":
    train_model()
