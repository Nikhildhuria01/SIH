# Download the English spaCy model once:
# python -m spacy download en_core_web_sm
# Then extend this script with your annotated FIR examples.
import spacy
print('Base NER model ready:', spacy.load('en_core_web_sm').meta['name'])
