"""Legacy-compatible synthetic relationship generator.

The hackathon's main training dataset is the realistic 600-person / 660-link
CSV already present in backend/data/relationships.csv. This script remains so
the original project structure is preserved.
"""
from pathlib import Path
import random
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "backend" / "data" / "relationship_pairs.csv"
random.seed(42)

names = ["Amit Verma", "Ravi Kumar", "Sahil Khan", "Neha Sharma", "Pooja Singh"]
rows = []
for _ in range(250):
    a, b = random.sample(names, 2)
    calls = random.randint(0, 20)
    txns = random.randint(0, 8)
    meetings = random.randint(0, 4)
    label = int(calls + txns * 2 + meetings * 3 >= 12)
    rows.append([a, b, calls, txns, meetings, label])

OUT.parent.mkdir(exist_ok=True)
pd.DataFrame(rows, columns=["person_a", "person_b", "calls", "transactions", "meetings", "label"]).to_csv(OUT, index=False)
print(f"Generated {len(rows)} legacy synthetic pair records at {OUT}")
