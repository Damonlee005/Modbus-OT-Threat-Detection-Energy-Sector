import pandas as pd

MITRE_MAP = {
    1:  {'technique_id': 'T0836', 'technique': 'Modify Parameter', 'tactic': 'Impair Process Control'},
    2:  {'technique_id': 'T0836', 'technique': 'Modify Parameter', 'tactic': 'Impair Process Control'},
    5:  {'technique_id': 'T0855', 'technique': 'Unauthorized Command Message', 'tactic': 'Impair Process Control'},
    6:  {'technique_id': 'T0855', 'technique': 'Unauthorized Command Message', 'tactic': 'Impair Process Control'},
    15: {'technique_id': 'T0843', 'technique': 'Program Download', 'tactic': 'Lateral Movement'},
    16: {'technique_id': 'T0843', 'technique': 'Program Download', 'tactic': 'Lateral Movement'},
    17: {'technique_id': 'T0845', 'technique': 'Program Upload', 'tactic': 'Collection'},
    20: {'technique_id': 'T0861', 'technique': 'Point & Tag Identification', 'tactic': 'Discovery'},
    43: {'technique_id': 'T0856', 'technique': 'Spoof Reporting Message', 'tactic': 'Impair Process Control'},
}

def map_to_mitre(df):
    anomalies = df[df['anomaly'] == -1].copy()

    def get_field(fc, field):
        try:
            return MITRE_MAP.get(int(fc), {}).get(field, 'Unknown / Unmapped')
        except (ValueError, TypeError):
            return 'Unknown / Unmapped'

    anomalies['technique_id'] = anomalies['function_code'].apply(lambda x: get_field(x, 'technique_id'))
    anomalies['technique'] = anomalies['function_code'].apply(lambda x: get_field(x, 'technique'))
    anomalies['tactic'] = anomalies['function_code'].apply(lambda x: get_field(x, 'tactic'))

    return anomalies

if __name__ == "__main__":
    df = pd.read_csv('data/results.csv')
    mapped = map_to_mitre(df)
    mapped.to_csv('data/mitre_mapped.csv', index=False)

    print(f"Mapped {len(mapped)} anomalies to MITRE ATT&CK for ICS")
    print(mapped[['timestamp', 'src_ip', 'function_code', 'technique_id', 'technique', 'tactic']].head(20))

    print("\nAnomalies by MITRE Technique:")
    print(mapped.groupby(['technique_id', 'technique']).size().reset_index(name='count').sort_values('count', ascending=False))
