import csv
import os
from pathlib import Path

from dotenv import load_dotenv
from supabase import create_client

# ============================================================
# LOAD ENVIRONMENT
# ============================================================

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
INVESTIGATION_ID = os.getenv("INVESTIGATION_ID")


if not SUPABASE_URL:
    raise RuntimeError("SUPABASE_URL is missing from backend/.env")

if not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY is missing from backend/.env")

if not INVESTIGATION_ID:
    raise RuntimeError("INVESTIGATION_ID is missing from backend/.env")


supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


# ============================================================
# DATA LOCATION
# ============================================================

DATA_DIR = Path(__file__).resolve().parents[1] / "data"

PERSONS_FILE = DATA_DIR / "persons.csv"
RELATIONSHIPS_FILE = DATA_DIR / "relationships.csv"


if not PERSONS_FILE.exists():
    raise FileNotFoundError(f"Could not find {PERSONS_FILE}")

if not RELATIONSHIPS_FILE.exists():
    raise FileNotFoundError(f"Could not find {RELATIONSHIPS_FILE}")


# ============================================================
# IMPORT PERSONS
# ============================================================

print()
print("=" * 60)
print("IMPORTING PERSONS")
print("=" * 60)

persons = []

with open(PERSONS_FILE, "r", encoding="utf-8-sig", newline="") as file:

    reader = csv.DictReader(file)

    for row in reader:

        person = {
            "person_id": row["person_id"],
            "investigation_id": INVESTIGATION_ID,
            "name": row["name"],
            "phone_num": row["phone_num"] or None,
            "age": int(row["age"]) if row["age"] else None,
            "location": row["location"] or None,
            "vehicle_num": row["vehicle_num"] or None,
            "org": row["org"] or None,
            "bank_account": row["bank_account"] or None,
            "crime_recorded": row["crime_recorded"] or None,
            "fir_text": row["fir_text"] or None,
            "fir_language": row["fir_language"] or None,
        }

        persons.append(person)


print(f"Persons found in CSV: {len(persons)}")


# Import in batches
BATCH_SIZE = 100

for i in range(0, len(persons), BATCH_SIZE):

    batch = persons[i : i + BATCH_SIZE]

    supabase.table("persons").upsert(batch, on_conflict="person_id").execute()

    end = min(i + BATCH_SIZE, len(persons))

    print(f"Imported persons " f"{i + 1}-{end}")


print(f"Total persons imported: " f"{len(persons)}")


# ============================================================
# IMPORT RELATIONSHIPS
# ============================================================

print()
print("=" * 60)
print("IMPORTING RELATIONSHIPS")
print("=" * 60)

relationships = []

with open(RELATIONSHIPS_FILE, "r", encoding="utf-8-sig", newline="") as file:

    reader = csv.DictReader(file)

    for row in reader:

        relationship = {
            "relationship_id": row["relationship_id"],
            "investigation_id": INVESTIGATION_ID,
            "person_a_id": row["person_a_id"],
            "person_a_name": row["person_a_name"],
            "person_b_id": row["person_b_id"],
            "person_b_name": row["person_b_name"],
            # --------------------------
            # Phone evidence
            # --------------------------
            "phone_call_count": int(row["phone_call_count"] or 0),
            "phone_call_dates": row["phone_call_dates"] or None,
            "phone_call_durations_sec": row["phone_call_durations_sec"] or None,
            "total_call_duration_sec": int(row["total_call_duration_sec"] or 0),
            # --------------------------
            # Transaction evidence
            # --------------------------
            "transaction_count": int(row["transaction_count"] or 0),
            "transaction_dates": row["transaction_dates"] or None,
            "transaction_amounts": row["transaction_amounts"] or None,
            "total_transaction_amount": float(row["total_transaction_amount"] or 0),
            # --------------------------
            # Meeting evidence
            # --------------------------
            "meeting_count": int(row["meeting_count"] or 0),
            "meeting_dates": row["meeting_dates"] or None,
            "meeting_locations": row["meeting_locations"] or None,
            # --------------------------
            # Relationship type
            # --------------------------
            "relationship_type": row["relationship_type"] or None,
            "relationship_description": row["relationship_description"] or None,
            # --------------------------
            # Dataset labels
            # --------------------------
            "relationship_label": int(row["relationship_label"] or 0),
            "ground_truth_confidence": float(row["ground_truth_confidence"] or 0),
        }

        relationships.append(relationship)


print(f"Relationships found in CSV: " f"{len(relationships)}")


for i in range(0, len(relationships), BATCH_SIZE):

    batch = relationships[i : i + BATCH_SIZE]

    supabase.table("person_relationships").upsert(
        batch, on_conflict="relationship_id"
    ).execute()

    end = min(i + BATCH_SIZE, len(relationships))

    print(f"Imported relationships " f"{i + 1}-{end}")


print(f"Total relationships imported: " f"{len(relationships)}")


# ============================================================
# COMPLETE
# ============================================================

print()
print("=" * 60)
print("DATABASE SEEDING COMPLETED")
print("=" * 60)
print()
print(f"Investigation ID: {INVESTIGATION_ID}")
print(f"Persons: {len(persons)}")
print(f"Relationships: {len(relationships)}")
print()
