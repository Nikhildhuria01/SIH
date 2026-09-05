"""Stylometry baseline for authorized investigative comparison.

Stylometry is probabilistic. It should be presented as a supporting signal, not
as definitive authorship or identity proof.
"""
from pathlib import Path
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parent
CSV = ROOT / "stylometry_demo.csv"
MODEL = ROOT / "stylometry.joblib"

df = pd.read_csv(CSV)
X_train, X_test, y_train, y_test = train_test_split(
    df.text,
    df.author,
    test_size=0.25,
    random_state=42,
    stratify=df.author,
)

model = Pipeline(
    [
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=30000)),
        ("clf", LogisticRegression(max_iter=3000)),
    ]
)
model.fit(X_train, y_train)
print(classification_report(y_test, model.predict(X_test)))
joblib.dump(model, MODEL)
print("Saved", MODEL)
