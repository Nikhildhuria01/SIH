from __future__ import annotations

import re
from typing import Dict, List

import spacy

try:
    nlp = spacy.load("en_core_web_sm")
except Exception:
    nlp = None

PATTERNS = {
    "PHONE": r"(?<!\d)(?:\+91[- ]?)?[6-9]\d{9}(?!\d)",
    "VEHICLE": r"\b(?:DL|HR|UP|PB)[- ]?\d{1,2}[- ]?[A-Z]{1,3}[- ]?\d{3,4}\b",
    "EMAIL": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
    "BANK": r"\b(?:XXXXXX)?\d{6,18}\b",
}


def _unique(values: List[str]) -> List[str]:
    seen = set()
    output = []
    for value in values:
        key = value.strip().lower()
        if key and key not in seen:
            seen.add(key)
            output.append(value.strip())
    return output


def extract_entities(text: str) -> Dict[str, List[str]]:
    out = {
        "PERSON": [],
        "ORG": [],
        "GPE": [],
        "PHONE": [],
        "VEHICLE": [],
        "EMAIL": [],
        "BANK": [],
    }

    if nlp is not None:
        doc = nlp(text)
        for ent in doc.ents:
            if ent.label_ == "PERSON":
                out["PERSON"].append(ent.text)
            elif ent.label_ == "ORG":
                out["ORG"].append(ent.text)
            elif ent.label_ in {"GPE", "LOC"}:
                out["GPE"].append(ent.text)

    for label, pattern in PATTERNS.items():
        matches = re.findall(pattern, text, flags=re.I)
        for match in matches:
            value = match[0] if isinstance(match, tuple) else match
            out[label].append(value)

    # A few safe cue-based patterns improve the synthetic/Indian demo corpus.
    for match in re.findall(r"\b(?:Mr\.?|Mrs\.?|Ms\.?)\s+([A-Z][a-z]+\s+[A-Z][a-z]+)\b", text):
        out["PERSON"].append(match)

    for label in out:
        out[label] = _unique(out[label])

    return out
