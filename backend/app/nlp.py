import re
import spacy

# Load English NLP model
try:
    nlp = spacy.load("en_core_web_sm")
except Exception:
    nlp = None


# Regex patterns for structured entities
PATTERNS = {
    "PHONE": r"(?<!\d)(?:\+91[- ]?)?[6-9]\d{9}(?!\d)",
    "VEHICLE": r"\b(?:DL|HR|UP|PB)-?\d{1,2}-?[A-Z]{1,3}-?\d{3,4}\b",
    "EMAIL": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
    "BANK": r"\b(?:XXXXXX)?\d{6,18}\b",
}


def extract_entities(text: str):
    """
    Extract entities from FIR / intelligence text.

    Returns:
    {
        "PERSON": [],
        "ORG": [],
        "GPE": [],
        "PHONE": [],
        "VEHICLE": [],
        "EMAIL": [],
        "BANK": []
    }
    """

    # Always initialize every supported entity type.
    # This prevents KeyError when regex results are added.
    out = {
        "PERSON": [],
        "ORG": [],
        "GPE": [],
        "PHONE": [],
        "VEHICLE": [],
        "EMAIL": [],
        "BANK": [],
    }

    # --------------------------------------------------
    # spaCy Named Entity Recognition
    # --------------------------------------------------

    if nlp is not None:
        doc = nlp(text)

        for ent in doc.ents:
            if ent.label_ == "PERSON":
                out["PERSON"].append(ent.text)

            elif ent.label_ == "ORG":
                out["ORG"].append(ent.text)

            elif ent.label_ in ["GPE", "LOC"]:
                out["GPE"].append(ent.text)

    # --------------------------------------------------
    # Regex-based extraction
    # --------------------------------------------------

    for label, pattern in PATTERNS.items():
        matches = re.findall(pattern, text, flags=re.I)

        for match in matches:

            # re.findall can return tuples for some patterns.
            if isinstance(match, tuple):
                value = match[0]
            else:
                value = match

            value = value.strip()

            if value:
                out[label].append(value)

    # --------------------------------------------------
    # Remove duplicates while preserving order
    # --------------------------------------------------

    for label in out:
        seen = set()
        cleaned = []

        for value in out[label]:
            normalized = value.lower()

            if normalized not in seen:
                seen.add(normalized)
                cleaned.append(value)

        out[label] = cleaned

    return out
