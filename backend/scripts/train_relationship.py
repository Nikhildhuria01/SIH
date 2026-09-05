"""Train NyayaNet relationship + suspicious-activity models.

Training inputs are the synthetic CSVs only. Live investigations never read
these CSVs to construct their graph; they only use the resulting model files.
"""
from __future__ import annotations

import json
import math
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "backend" / "data"
RELATIONSHIPS = DATA_DIR / "relationships.csv"
PERSONS = DATA_DIR / "persons.csv"
ML = ROOT / "ml"
ML.mkdir(exist_ok=True)

FEATURE_NAMES = [
    "log_calls",
    "log_call_duration",
    "log_transactions",
    "log_transaction_amount",
    "log_meetings",
    "log_co_occurrences",
    "source_diversity",
    "shared_phone",
    "shared_vehicle",
    "shared_org",
    "shared_location",
]


def norm(value):
    if pd.isna(value):
        return ""
    return str(value).strip().lower()


def feature_frame(rel_df: pd.DataFrame, persons_df: pd.DataFrame) -> pd.DataFrame:
    persons = persons_df.set_index("person_id", drop=False)
    rows = []

    for _, row in rel_df.iterrows():
        calls = float(pd.to_numeric(row.get("phone_call_count", 0), errors="coerce") or 0)
        duration = float(pd.to_numeric(row.get("total_call_duration_sec", 0), errors="coerce") or 0)
        txns = float(pd.to_numeric(row.get("transaction_count", 0), errors="coerce") or 0)
        amount = float(pd.to_numeric(row.get("total_transaction_amount", 0), errors="coerce") or 0)
        meetings = float(pd.to_numeric(row.get("meeting_count", 0), errors="coerce") or 0)
        co_occ = float(calls + txns + meetings)
        source_diversity = float(
            int(calls > 0) + int(txns > 0) + int(meetings > 0)
        )

        a = persons.loc[row["person_a_id"]] if row["person_a_id"] in persons.index else None
        b = persons.loc[row["person_b_id"]] if row["person_b_id"] in persons.index else None

        def same(field):
            if a is None or b is None:
                return 0.0
            av = norm(a.get(field))
            bv = norm(b.get(field))
            return float(bool(av and bv and av == bv))

        # The CSV relationship labels remain the synthetic target only.
        rows.append(
            {
                "log_calls": math.log1p(calls),
                "log_call_duration": math.log1p(duration),
                "log_transactions": math.log1p(txns),
                "log_transaction_amount": math.log1p(amount),
                "log_meetings": math.log1p(meetings),
                "log_co_occurrences": math.log1p(co_occ),
                "source_diversity": source_diversity,
                "shared_phone": same("phone_num"),
                "shared_vehicle": same("vehicle_num"),
                "shared_org": same("org"),
                "shared_location": same("location"),
            }
        )

    return pd.DataFrame(rows, columns=FEATURE_NAMES)


def main():
    rel = pd.read_csv(RELATIONSHIPS)
    persons = pd.read_csv(PERSONS)
    rel["relationship_label"] = pd.to_numeric(
        rel["relationship_label"], errors="coerce"
    ).fillna(0).astype(int)

    X = feature_frame(rel, persons)
    y = rel["relationship_label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    model = Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "classifier",
                LogisticRegression(max_iter=3000, class_weight="balanced"),
            ),
        ]
    )
    model.fit(X_train, y_train)
    preds = model.predict(X_test)
    probs = model.predict_proba(X_test)[:, 1]

    print(classification_report(y_test, preds))
    print("ROC-AUC:", round(roc_auc_score(y_test, probs), 4))

    joblib.dump(model, ML / "relationship_model.joblib")

    anomaly = IsolationForest(
        n_estimators=300,
        contamination=0.10,
        random_state=42,
    )
    anomaly.fit(X)
    joblib.dump(anomaly, ML / "suspicious_pattern_model.joblib")

    (ML / "relationship_features.json").write_text(
        json.dumps({"feature_names": FEATURE_NAMES}, indent=2),
        encoding="utf-8",
    )

    print("Saved relationship_model.joblib")
    print("Saved suspicious_pattern_model.joblib")
    print("Saved relationship_features.json")


if __name__ == "__main__":
    main()
