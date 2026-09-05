# NyayaNet — implementation plan aligned to the actual investigator workflow

## 1. Investigator access and case management

- Authorized login through Supabase Auth + `profiles.is_authorized`.
- Sidebar separates ongoing, closed and all investigations.
- Investigator can start a new investigation.
- Investigator can close a completed investigation.
- Each case has a generated investigation code.

## 2. Multi-source investigation intake

A case can receive:

- FIR / police complaint
- police reports
- financial transaction records
- surveillance reports
- social-media intelligence
- criminal-history records

The original source text is preserved with source type, title, language and content hash.

## 3. Entity intelligence

For every source:

```text
source text
   ↓
language / text preprocessing
   ↓
NER + structured regex extraction
   ↓
PERSON / LOCATION / VEHICLE / PHONE / ORG / EMAIL / BANK
   ↓
normalization + conservative entity resolution
```

Do not blindly copy the first phone/vehicle/organization from a multi-person document onto every person.

## 4. Candidate relationship generation

For every pair of persons appearing in common evidence, calculate observable features such as:

- phone-call signals
- transaction signals
- meeting signals
- co-occurrence count
- source diversity
- shared phone / vehicle / organization / location

The system generates a **candidate relationship** rather than asserting a social or criminal relationship.

## 5. ML relationship score

Train on the realistic synthetic `backend/data/relationships.csv`.

The classifier predicts the likelihood that the observed pair of records represents a relationship signal.

Training inputs intentionally exclude:

- relationship type
- relationship description
- ground-truth confidence

The score is displayed as an analytical confidence/lead score.

## 6. Suspicious activity detection

Use two layers:

### Statistical/anomaly layer
IsolationForest identifies unusual combinations of calls, call duration, transaction counts/value, meetings and evidence activity.

### Explainable rule layer
Flag patterns such as:

- unusually frequent communications
- repeated financial activity
- high aggregate transaction value
- repeated meetings
- evidence spanning multiple source types
- shared identifying attributes

A suspicious-pattern flag is an investigation aid, not a finding of guilt.

## 7. Network construction

The main graph is investigator-driven:

```text
Search subject
      ↓
Select matching person
      ↓
Center selected person
      ↓
Show all connected candidate relationships
      ↓
Relationship type + score + evidence
```

The graph supports search, drag, pan, zoom, node hover and relationship inspection.

## 8. Influential individuals

Use NetworkX to calculate:

- degree centrality
- betweenness centrality
- PageRank

These are network-structure measures and should be described as such.

## 9. Investigation analytics dashboard

Expose:

- sources processed
- entities extracted
- candidate links
- suspicious-pattern signals
- influential individuals
- top relationship leads

## 10. Integrity and auditability

Hash original source documents and append important analytical actions to the audit log.

A hash chain is tamper-evident, not automatically immutable.

## 11. Regional languages

Current pipeline stores `language` and preserves original text.

Next language milestone:

- Hindi NER
- Punjabi NER
- transliteration support
- language-aware normalization

Translated text must remain separate from original evidence.

## 12. Evaluation

Relationship model:

- precision / recall / F1
- ROC-AUC / PR-AUC
- calibration
- false-positive analysis

Suspicious patterns:

- detection precision on labeled synthetic scenarios
- analyst-review usefulness

Graph:

- search latency
- correct subject-to-neighbor retrieval
- evidence provenance correctness

Security:

- RLS tests
- authorization tests
- audit-chain verification

**Important:** evaluation on the supplied synthetic dataset is demonstration evidence, not evidence of real-world law-enforcement performance.
