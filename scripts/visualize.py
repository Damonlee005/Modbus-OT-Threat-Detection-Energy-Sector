import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import os

os.makedirs('visualizations', exist_ok=True)

df = pd.read_csv('data/results.csv')
mapped = pd.read_csv('data/mitre_mapped.csv')

plt.rcParams['figure.facecolor'] = 'white'
plt.rcParams['axes.facecolor'] = '#f8f9fa'
plt.rcParams['axes.grid'] = True
plt.rcParams['grid.alpha'] = 0.4
plt.rcParams['font.family'] = 'sans-serif'

# Chart 1 — Normal vs Anomalous
counts = df['anomaly_label'].value_counts()
colors = ['#1565C0', '#C62828']

fig, ax = plt.subplots(figsize=(8, 5))
bars = ax.bar(counts.index, counts.values, color=colors,
              edgecolor='white', linewidth=1.5, width=0.5)
ax.set_title('Normal vs Anomalous Packet Distribution',
             fontsize=15, fontweight='bold', pad=15)
ax.set_xlabel('Classification', fontsize=12)
ax.set_ylabel('Packet Count', fontsize=12)
ax.yaxis.set_major_formatter(mticker.FuncFormatter(
    lambda x, p: f'{int(x):,}'))

for bar, val in zip(bars, counts.values):
    ax.text(bar.get_x() + bar.get_width() / 2,
            bar.get_height() + bar.get_height() * 0.01,
            f'{int(val):,}', ha='center', va='bottom',
            fontsize=11, fontweight='bold')

ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
plt.tight_layout()
plt.savefig('visualizations/anomaly_distribution.png', dpi=150, bbox_inches='tight')
plt.close()
print("Saved: anomaly_distribution.png")

# Chart 2 — MITRE Technique Breakdown (excluding Unknown)
known = mapped[mapped['technique'] != 'Unknown / Unmapped']
technique_counts = known.groupby('technique').size().sort_values(ascending=True)

fig, ax = plt.subplots(figsize=(11, 6))
bars = technique_counts.plot(kind='barh', ax=ax, color='#1565C0',
                              edgecolor='white', linewidth=1)
ax.set_title('Anomalies by MITRE ATT&CK for ICS Technique',
             fontsize=14, fontweight='bold', pad=15)
ax.set_xlabel('Anomaly Count', fontsize=12)
ax.set_ylabel('')
ax.xaxis.set_major_formatter(mticker.FuncFormatter(
    lambda x, p: f'{int(x):,}'))

for i, (val, patch) in enumerate(zip(technique_counts.values,
                                      ax.patches)):
    ax.text(val + val * 0.01, patch.get_y() + patch.get_height() / 2,
            f'{int(val):,}', va='center', fontsize=10, fontweight='bold')

ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
plt.tight_layout()
plt.savefig('visualizations/mitre_technique_breakdown.png', dpi=150,
            bbox_inches='tight')
plt.close()
print("Saved: mitre_technique_breakdown.png")

print("\nDone. Charts saved to /visualizations")
