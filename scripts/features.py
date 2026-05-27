import pandas as pd
import numpy as np


def engineer_features(df):
    df = df.dropna(subset=['function_code'])
    df = df.sort_values('timestamp').reset_index(drop=True)

    df['time_delta'] = df['timestamp'].diff().fillna(0)
    df['length_mean'] = df['length'].rolling(window=10, min_periods=1).mean()
    df['length_deviation'] = abs(df['length'] - df['length_mean'])

    fc_counts = df.groupby(['src_ip', 'function_code']).size().reset_index(name='fc_frequency')
    df = df.merge(fc_counts, on=['src_ip', 'function_code'], how='left')

    feature_columns = [
        'function_code',
        'length',
        'time_delta',
        'length_deviation',
        'fc_frequency'
    ]

    features = df[feature_columns]
    return features, df


if __name__ == "__main__":
    df = pd.read_csv('data/parsed_traffic.csv')
    features, enriched_df = engineer_features(df)
    enriched_df.to_csv('data/enriched_traffic.csv', index=False)
    print(f"Feature engineering complete. {len(features)} records processed.")
    print("\nFeature preview:")
    print(features.head(10))