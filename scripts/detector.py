import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os


def train_model(features):
    scaler = StandardScaler()
    X = scaler.fit_transform(features)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )
    model.fit(X)

    os.makedirs('models', exist_ok=True)
    joblib.dump(model, 'models/isolation_forest.pkl')
    joblib.dump(scaler, 'models/scaler.pkl')
    print("Model trained and saved to /models")

    return model, scaler


def detect_anomalies(features, model, scaler):
    X = scaler.transform(features)
    predictions = model.predict(X)
    scores = model.decision_function(X)
    return predictions, scores


if __name__ == "__main__":
    df = pd.read_csv('data/enriched_traffic.csv')

    feature_cols = ['function_code', 'length', 'time_delta', 'length_deviation', 'fc_frequency']
    features = df[feature_cols].fillna(0)

    model, scaler = train_model(features)

    predictions, scores = detect_anomalies(features, model, scaler)

    df['anomaly'] = predictions
    df['anomaly_score'] = scores
    df['anomaly_label'] = df['anomaly'].map({1: 'Normal', -1: 'Anomaly'})

    df.to_csv('data/results.csv', index=False)

    anomalies = df[df['anomaly'] == -1]
    print(f"\nTotal packets analyzed: {len(df)}")
    print(f"Anomalies detected: {len(anomalies)}")
    print(f"Detection rate: {len(anomalies)/len(df)*100:.2f}%")
    print("\nSample anomalies:")
    print(anomalies[['timestamp', 'src_ip', 'function_code', 'anomaly_score']].head(20))