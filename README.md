# SIH 2026 — Problem Statement 26189: AI-Powered Criminal Network Analysis

**Prototype:** NyayaNet

NyayaNet is an authorized-investigator prototype for turning multiple intelligence sources into a structured, explainable criminal-network analysis workspace.

The intended workflow is:

```text
Investigator login
      ↓
Start new investigation / open ongoing / review closed
      ↓
Provide available intelligence sources
  • FIR / police complaint
  • police reports
  • financial transaction records
  • surveillance reports
  • social-media intelligence
  • criminal-history records
      ↓
Preserve source + hash
      ↓
NLP entity extraction + normalization
  PERSON / LOCATION / VEHICLE / PHONE / ORG / EMAIL / BANK
      ↓
Candidate relationship generation
      ↓
ML relationship score
      ↓
Suspicious-pattern detection
      ↓
Graph analytics
  • relationship map
  • influential individuals
  • suspicious activity signals
      ↓
Explainable investigator dashboard
```

## Existing project structure

The directory structure is intentionally unchanged. The main updates stay inside the existing `frontend/src`, `backend/app`, `backend/scripts`, `db`, `ml`, and `docs` files. The realistic India/NCR two-CSV dataset is stored in `backend/data/persons.csv` and `backend/data/relationships.csv`.

## Architecture

```text
React + Vite
      │
      ├── Supabase Auth (publishable key only)
      │
      └── FastAPI API (server-only Supabase service key)
                │
                ├── PostgreSQL / RLS
                ├── source document storage metadata + SHA-256 hashes
                ├── spaCy + regex entity extraction
                ├── relationship classifier
                ├── IsolationForest suspicious-pattern detector
                └── NetworkX centrality analytics
```

Never expose the Supabase service-role key in the browser.

## Investigator experience

After login, an authorized investigator can start a new investigation or select an ongoing/closed investigation from the sidebar.

Starting an investigation opens a source-intake workspace. The investigator provides the available FIR, police-report, financial, surveillance, social-media, and criminal-history information. At least one source is required; sources that do not exist for a case can remain empty.

NyayaNet preserves the original source text, extracts entities, creates candidate relationships when people co-occur across evidence, scores those candidates with the trained model, and flags unusual activity combinations. The graph and analytics are restricted to the selected investigation.

## Machine-learning models

### Relationship model

The 600-person / 660-relationship synthetic dataset in `backend/data/relationships.csv` is used to train the relationship classifier. The model uses observable activity features including:

- phone-call frequency
- total call duration
- transaction count
- total transaction value
- meeting count
- evidence/activity co-occurrence
- source diversity
- shared phone / vehicle / organization / location signals when available during live analysis

`relationship_type`, `relationship_description`, and `ground_truth_confidence` are **not** used as model inputs.

The output is a **candidate relationship confidence**, not a probability of guilt.

### Suspicious-pattern model

An IsolationForest model learns unusual combinations of activity features and complements transparent rules such as unusually frequent calls, repeated transactions, high aggregate transaction value, repeated meetings, and cross-source activity.

### Influence analysis

NetworkX is used to calculate degree centrality, betweenness centrality, and PageRank. These are structural network measures. They are not criminality scores.

## Train the models

From the project root:

```bash
cd backend
python scripts/train_relationship.py
```

This creates:

```text
ml/relationship_model.joblib
ml/suspicious_pattern_model.joblib
ml/relationship_features.json
```

The validation numbers printed by the training script are for the synthetic demo dataset only and must not be presented as real-world law-enforcement performance.

## Run the backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

Put the Supabase URL, publishable key, and **server-only** service-role key in `backend/.env`.

Run on the port used by the current frontend setup:

```bash
python -m uvicorn app.main:app --port 8080
```

Health check:

```text
http://127.0.0.1:8080/health
```

API documentation:

```text
http://127.0.0.1:8080/docs
```

## Run the frontend

```bash
cd frontend
npm install
npm run dev
```

Set:

```env
VITE_API_URL=http://localhost:8080
```

in `frontend/.env`.

## Supabase data model

Core live tables:

- `profiles`
- `investigations`
- `documents`
- `persons`
- `person_relationships`
- `analysis_runs`
- `audit_log`

Legacy `entities` and `network_links` remain in the schema for compatibility with the original starter.

## Synthetic dataset

The supplied demonstration dataset contains:

- 600 synthetic Indian persons
- NCR-focused locations
- names, phones, ages, vehicles, organizations, masked bank identifiers, crime-recorded fields, FIR text and language metadata
- 660 synthetic relationship records
- phone-call details, transaction details, meeting details
- synthetic relationship-type labels such as Friend, Family, Business Associate, Partner, etc.

Those relationship-type labels are demo reference labels. In a new investigation, NyayaNet should generate a **candidate relationship** from the observed evidence rather than inventing a social relationship that has not been supplied by an authoritative source.

## Security / integrity framing

SHA-256 content and hash-chain records make later changes detectable; hashing alone is not an immutable storage system. A production deployment would need an append-only/WORM or equivalent evidence-preservation layer and independent audit copies.

The relationship model is an investigative lead generator. It must not be described as identifying criminals or proving guilt.

## Demo sequence for SIH

1. Authorized investigator logs in.
2. Start a new investigation.
3. Enter a title, scope, and one or more intelligence sources.
4. Run source analysis.
5. Review extracted entities.
6. Review candidate relationship scores.
7. Review suspicious-activity signals.
8. Inspect influential individuals.
9. Search a person in the graph and inspect all connected relationships.
10. Hover a node to inspect person metadata and click a relationship to inspect its evidence explanation.
11. Close the investigation when the case is complete.

## Important prototype limitations

The NLP baseline is strongest on English and structured patterns. Hindi and Punjabi are preserved with language metadata, while dedicated Indic-language NER/transliteration models remain a future improvement.

Entity resolution from free-form evidence is conservative: when a document mentions multiple people and several shared attributes, the system does not blindly assign the first phone/vehicle/organization to every person. This reduces false attribution.
