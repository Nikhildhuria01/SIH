# Step-by-step implementation plan

## Step 1 — establish the data contract
Define canonical entity types and relation types before training models.

Entity types: PERSON, ORG, LOCATION, PHONE, VEHICLE, ACCOUNT, DOCUMENT, EVENT.

Relations: ASSOCIATED_WITH, CALLED, TRANSACTED_WITH, LOCATED_AT, WORKS_FOR, OWNS, MET, MENTIONED_IN.

Every relationship should store: source, target, type, reason, confidence, evidence IDs, creator, timestamp, previous hash, current hash.

## Step 2 — ingestion
Build adapters that transform each source into one normalized event format. Preserve source metadata and original content.

## Step 3 — NLP
Run language detection → sentence segmentation → NER → normalization → entity resolution.

Example normalization:
- phones: E.164-ish canonical format
- vehicles: uppercase and remove spaces/dashes
- person names: whitespace/case normalization while retaining original display value

## Step 4 — entity resolution
Use exact rules first, then fuzzy similarity/embeddings. Never auto-merge high-impact entities without review.

## Step 5 — relationship candidates
Generate candidate pairs from co-occurrence, CDR overlap, financial links, shared addresses, common organizations, common vehicles, event overlap and temporal proximity.

## Step 6 — ML score
Train a classifier on labeled pairs. Keep the feature vector visible to investigators so a candidate link is explainable.

## Step 7 — graph analytics
Compute degree, betweenness, PageRank/eigenvector-like influence and communities. Label these as network-centrality measures, not criminality scores.

## Step 8 — stylometry
Extract character/word n-gram style features. Compare documents only where there is a legitimate investigative basis. Report probability and uncertainty.

## Step 9 — integrity
For each immutable event: canonical JSON → SHA-256(event + previous hash). Store both hashes. Export the chain for independent verification.

## Step 10 — regional language
Store `original_text`, `language`, `translated_text` separately. Extract entities from the original where possible. Add Hindi NER and transliteration as a dedicated model stage.

## Step 11 — evaluation
NER: precision/recall/F1.
Relationship model: precision/recall/F1, PR-AUC, calibration.
Stylometry: cross-validation, confusion matrix, false-positive analysis.
Graph: query latency and correctness of provenance.
Security: RLS tests, role tests, tamper-detection tests.

## Step 12 — demo story
Use one synthetic tip. Extract 4–8 entities. Expand the network using synthetic CDR/transaction/location records. Show 2–3 candidate links, each with a different reason. Show one hash-chain verification. Then show the investigator rejecting one weak link and confirming one after reviewing evidence.
