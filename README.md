# SIH 2026 — Problem Statement 26189: AI-Powered Criminal Network Analysis

**Prototype name:** NyayaNet

This repository is a hackathon starter, not a production law-enforcement system. It demonstrates a privacy-aware workflow for authorized investigators: Supabase authentication → investigation workspace → document ingestion → NLP entity extraction → explainable candidate relationships → graph → append-only hash chain.

## 1. Recommended architecture

```text
React + Vite frontend
        |
        | Supabase Auth (publishable key)
        v
Supabase Auth + Postgres + Storage
        ^
        | RLS / authorized investigator access
        |
FastAPI backend (server-only service key)
   |        |         |
   |        |         +--> ML relationship scorer
   |        +------------> NLP / NER / stylometry
   +---------------------> hashing + audit log
```

### Why separate frontend/backend?
- React handles investigator UI and visualization.
- Supabase handles identity, PostgreSQL, RLS and optional Storage.
- FastAPI owns sensitive processing, model inference and controlled writes.
- Never put the Supabase service-role key in React.

## 2. Features mapped to the problem statement

1. FIR/intelligence ingestion.
2. NLP entity extraction: people, organizations, places, phones, vehicles, emails.
3. Entity normalization and deduplication (next milestone).
4. Relationship graph with relation type, confidence and reason.
5. Candidate relationship ML model.
6. Stylometry baseline for comparing writing style.
7. Tip-to-network: extract entities from a small tip and use them as graph seeds.
8. Investigation ID generation in PostgreSQL.
9. Regional-language UI/data pipeline (architecture-ready; add Indic NLP/translation models after English baseline works).
10. Hash-chained links and audit events.
11. Authorized-login gate using Supabase + profiles.is_authorized.

## 3. Important security design

A SHA-256 hash makes tampering detectable; it does not magically make a database immutable. For the SIH demo, every link stores `previous_hash` + `link_hash`, producing a hash chain. For a real deployment, add an append-only/WORM evidence store or an external notarization service and retain independent audit copies.

Do not describe an ML relationship score as proof of criminal association. UI wording should say **candidate link / analytical lead**, show the evidence/reason, and require human corroboration.

## 4. Supabase setup

1. Create a Supabase project.
2. Open SQL Editor and run `db/schema.sql`.
3. Create at least one user in Authentication, or sign up through the app.
4. In `public.profiles`, set that user's `is_authorized = true` and appropriate role (`admin`, `supervisor`, `investigator`, or `analyst`).
5. Copy Project URL and Publishable Key from the Supabase Connect/API area.
6. Keep the Service Role Key server-only.
7. Optional later: create a Storage bucket for source documents and protect it with RLS.

Current Supabase React guidance uses Vite + `@supabase/supabase-js` and environment variables such as `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY`. See the official docs linked in the project handoff.

## 5. Backend setup — Windows/macOS/Linux

```bash
cd backend
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows PowerShell
# .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
python -m spacy download en_core_web_sm
cp .env.example .env
```

Edit `.env` with your Supabase values.

Run:
```bash
uvicorn app.main:app --reload --port 8000
```

Test:
```bash
curl http://localhost:8000/health
```

API docs: `http://localhost:8000/docs`

## 6. Frontend setup

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

Open the Vite URL shown in the terminal, normally `http://localhost:5173`.

## 7. Demo flow

1. Create/sign into an authorized account.
2. Click **New investigation**.
3. Paste the synthetic FIR from `backend/data/fir_demo.txt` into Tip-to-network analysis.
4. Click **Extract entities**.
5. Later, create entity rows from the extracted results and add relationship links through the backend.
6. Refresh the graph.

The current starter intentionally keeps evidence creation behind backend APIs rather than allowing unrestricted browser writes.

## 8. Train the relationship model

```bash
cd backend
python scripts/generate_synthetic.py
python scripts/train_relationship.py
```

The synthetic model uses transparent features:
- same organization
- shared location
- shared phone
- number of co-occurrences

For SIH, present the score as **relationship candidate confidence**, not guilt probability.

## 9. Train the stylometry baseline

```bash
cd ml
python stylometry.py
```

This demo uses character n-grams + logistic regression. In the final project, evaluate with cross-validation and confidence thresholds, and explicitly state that stylometry is probabilistic and can be affected by language, editing, translation, shared templates, and short text.

## 10. NLP / NER training roadmap

Start with spaCy's pretrained English NER model. Then annotate a small synthetic/authorized corpus with labels such as:

`PERSON`, `ORG`, `GPE`, `PHONE`, `VEHICLE`, `CASE_ID`, `ACCOUNT`, `DATE`, `EMAIL`.

Create train/dev/test splits. Train a custom NER component and measure precision, recall and F1 per entity class. For Indian regional languages, add language-specific models/tokenizers instead of translating everything blindly.

## 11. Datasets

The earlier image referenced in the conversation is not available as a file in this workspace, so this repository does **not** claim to contain those exact datasets. Put authorized datasets into `backend/data/` and create importers for each schema.

Use synthetic data for the hackathon demo whenever real crime data is unavailable. Never use real victim/suspect PII in a public repository.

Recommended synthetic tables:
- persons.csv
- organizations.csv
- locations.csv
- phone_records.csv
- cdr.csv
- transactions.csv
- vehicles.csv
- fir_documents.csv
- surveillance_events.csv
- social_posts.csv

## 12. Suggested database model

`investigations` 1→N `documents`

`investigations` 1→N `entities`

`entities` N↔N `entities` through `network_links`

`documents` → extracted entities → candidate links → analyst verification → confirmed/ rejected status (add status fields in the next milestone).

## 13. SIH demo screens

- Login / authoritative access
- Investigation dashboard
- Create investigation / generated investigation ID
- Data ingestion
- NLP extraction panel
- Entity profile
- Network graph
- Relationship explanation panel
- Candidate-link review queue
- Stylometry comparison
- Evidence integrity / hash-chain audit
- Regional language switch
- Exportable investigation summary

## 14. What to build next

### Phase 1 — working MVP
Auth → investigations → FIR upload/paste → NER → entities → manual links → graph.

### Phase 2 — intelligence
Candidate-link model → feature explanation → suspicious-pattern rules → centrality/community detection.

### Phase 3 — integrity
Hash chain → audit log → evidence storage → signed exports → independent timestamp/notarization.

### Phase 4 — regional language
Hindi first, then other required languages. Keep original text and extracted-language metadata; never overwrite original evidence with translated text.

### Phase 5 — SIH polish
Role-based dashboard, clean graph UX, search, filters, timeline, evidence provenance, evaluation metrics and a 3–5 minute demo scenario using only synthetic data.
