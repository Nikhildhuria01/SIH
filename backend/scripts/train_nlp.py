"""NLP model bootstrap/validation script for the English spaCy baseline."""
import spacy

try:
    model = spacy.load("en_core_web_sm")
except Exception as exc:
    raise SystemExit(
        "Install the English model first: python -m spacy download en_core_web_sm"
    ) from exc

print("Base NER model ready:", model.meta.get("name", "en_core_web_sm"))
print("Supported labels in the live pipeline: PERSON, ORG, GPE/LOC + regex PHONE, VEHICLE, EMAIL, BANK")
