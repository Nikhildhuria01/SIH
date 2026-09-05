from __future__ import annotations

import re
from typing import Dict, List

import spacy

try:
    nlp = spacy.load("en_core_web_sm")
except Exception as exc:  # pragma: no cover - environment-dependent
    nlp = None
    # This failure is silent to the investigator but fatal to the pipeline:
    # with no PERSON entities, analyze-sources still "succeeds" (documents
    # get saved, regex-based entities like phone/vehicle still count up)
    # but zero candidate relationships, zero graph nodes, zero suspicious
    # patterns and zero influential persons are ever produced. Make it loud.
    print(
        "=" * 78
        + "\n[nlp] spaCy model 'en_core_web_sm' is NOT installed. PERSON / ORG / "
        "LOCATION\n[nlp] extraction from free-form evidence is disabled, so "
        "relationship candidates,\n[nlp] the network graph, suspicious-pattern "
        "detection and influential-person scoring\n[nlp] will all come back "
        "empty even though sources are being saved correctly.\n[nlp] Fix: "
        "inside the backend virtualenv run, then restart uvicorn:\n"
        "[nlp]     python -m spacy download en_core_web_sm\n"
        f"[nlp] underlying error: {exc}\n" + "=" * 78
    )

# Surfaced on GET /health so this is easy to verify without reading server logs.
NLP_MODEL_LOADED = nlp is not None

PATTERNS = {
    "PHONE": r"(?<!\d)(?:\+91[- ]?)?[6-9]\d{9}(?!\d)",
    "VEHICLE": r"\b(?:DL|HR|UP|PB)[- ]?\d{1,2}[- ]?[A-Z]{1,3}[- ]?\d{3,4}\b",
    "EMAIL": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
    "BANK": r"\b(?:XXXXXX)?\d{6,18}\b",
}

# Words that should stop the Title-Case fallback below from mistaking an
# organisation, locality, or sentence-leading word for a person's name.
_NON_PERSON_LEAD_WORDS = {
    "the",
    "this",
    "that",
    "these",
    "those",
    "it",
    "on",
    "in",
    "at",
    "a",
    "an",
    "his",
    "her",
    "their",
    "after",
    "before",
    "during",
    "following",
    "case",
    "fir",
    "report",
    "note",
    "record",
    "and",
    "but",
    "new",
    "old",
    "greater",
    "north",
    "south",
    "east",
    "west",
    "upper",
    "lower",
}
_NON_PERSON_SECOND_WORDS = {
    "logistics",
    "enterprises",
    "bank",
    "motors",
    "traders",
    "solutions",
    "industries",
    "group",
    "corporation",
    "corp",
    "services",
    "technologies",
    "technology",
    "international",
    "company",
    "ltd",
    "pvt",
    "llp",
    "foundation",
    "trust",
    "hospital",
    "college",
    "university",
    "school",
    "society",
    "apartments",
    "residency",
    "chowk",
    "nagar",
    "colony",
    "road",
    "marg",
    "sector",
    "complex",
    "towers",
    "mall",
    "bazar",
    "bazaar",
    "market",
    "town",
    "place",
    "park",
    "vihar",
    "puram",
    "extension",
    "enclave",
    "station",
    "police",
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


def _fallback_person_names(text: str, already_found: Dict[str, List[str]]) -> List[str]:
    """Conservative Title-Case bigram heuristic.

    Runs regardless of whether the spaCy model above loaded, so it also
    helps when the small English model misses a name it was never trained
    on (the project README already flags this as a known limitation for
    Hindi/Punjabi and less-common Indian names). It intentionally skips a
    candidate rather than risk mislabeling an organisation or locality as
    a person — see the stoplists above.
    """
    known_non_person = {
        v.strip().lower()
        for label in ("ORG", "GPE")
        for v in already_found.get(label, [])
    }

    names: List[str] = []
    for match in re.finditer(r"\b([A-Z][a-z]+)\s+([A-Z][a-z]+)\b", text):
        first, second = match.group(1), match.group(2)
        if first.lower() in _NON_PERSON_LEAD_WORDS:
            continue
        if second.lower() in _NON_PERSON_SECOND_WORDS:
            continue
        full = f"{first} {second}"
        if full.lower() in known_non_person:
            continue
        names.append(full)
    return names


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
    for match in re.findall(
        r"\b(?:Mr\.?|Mrs\.?|Ms\.?)\s+([A-Z][a-z]+\s+[A-Z][a-z]+)\b", text
    ):
        out["PERSON"].append(match)

    # Supplementary heuristic so PERSON extraction degrades gracefully
    # instead of silently returning nothing when spaCy can't be used
    # (see the NLP_MODEL_LOADED warning above).
    for name in _fallback_person_names(text, out):
        out["PERSON"].append(name)

    # A phone number should not also be reported as a bank account number
    # (both patterns can match a bare 10-digit number).
    phone_digits = {re.sub(r"\D", "", p) for p in out["PHONE"]}
    out["BANK"] = [b for b in out["BANK"] if re.sub(r"\D", "", b) not in phone_digits]

    for label in out:
        out[label] = _unique(out[label])

    return out
