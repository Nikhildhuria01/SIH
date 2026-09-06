from __future__ import annotations

import itertools
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


# Keep NLP lazy: importing the NLP module may load spaCy/model data and block startup.
def extract_entities(text: str):
    from .nlp import extract_entities as _extract_entities

    return _extract_entities(text)


from .security import hash_link, sha256_json, utc_now
from .supabase_client import supabase

app = FastAPI(
    title="NyayaNet — AI-Powered Criminal Network Analysis API",
    version="1.1.1",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ROOT = Path(__file__).resolve().parents[2]
MODEL_DIR = ROOT / "ml"
RELATIONSHIP_MODEL_PATH = MODEL_DIR / "relationship_model.joblib"
ANOMALY_MODEL_PATH = MODEL_DIR / "suspicious_pattern_model.joblib"
FEATURE_META_PATH = MODEL_DIR / "relationship_features.json"


def load_model(path: Path):
    """Load a model only when inference actually needs it.

    Keeping joblib/model deserialization out of module import prevents the
    FastAPI process from blocking before Application startup complete.
    """
    try:
        import joblib

        if not path.exists():
            return None
        return joblib.load(path)
    except Exception as exc:
        print(f"Model load failed for {path}: {exc}")
        return None


RELATIONSHIP_MODEL = None
ANOMALY_MODEL = None
FEATURE_META: Dict[str, Any] = {}
if FEATURE_META_PATH.exists():
    try:
        FEATURE_META = json.loads(FEATURE_META_PATH.read_text(encoding="utf-8"))
    except Exception:
        FEATURE_META = {}


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------


class InvestigationCreate(BaseModel):
    title: str
    description: Optional[str] = None


class SourceInput(BaseModel):
    source_type: str = ""
    title: Optional[str] = None
    content: str = ""
    language: str = "en"


class InvestigationAnalyzeRequest(BaseModel):
    sources: List[SourceInput] = Field(default_factory=list)


class DocumentIn(BaseModel):
    investigation_id: str
    source_type: str
    title: str
    content: str
    language: str = "en"


class LinkIn(BaseModel):
    investigation_id: str
    source_entity_id: str
    target_entity_id: str
    relation_type: str
    reason: str
    confidence: float = Field(ge=0, le=1)
    evidence_ids: List[str] = Field(default_factory=list)


class TipIn(BaseModel):
    investigation_id: str
    text: str


# -----------------------------------------------------------------------------
# Authentication
# -----------------------------------------------------------------------------


def require_user(authorization: Optional[str]) -> str:
    if supabase is None:
        raise HTTPException(500, "Supabase not configured")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Access token required")

    token = authorization.split(" ", 1)[1]
    try:
        user = supabase.auth.get_user(token).user
    except Exception as exc:
        print("Token validation failed:", exc)
        raise HTTPException(401, "Invalid token")

    profile = (
        supabase.table("profiles").select("is_authorized").eq("id", user.id).execute()
    )
    if not profile.data or not profile.data[0]["is_authorized"]:
        raise HTTPException(403, "User not authorized")
    return user.id


# -----------------------------------------------------------------------------
# Generic helpers
# -----------------------------------------------------------------------------


def clean_phone(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    phone = re.sub(r"[\s-]", "", str(value))
    if phone.startswith("+91"):
        phone = phone[3:]
    return phone


def normalize_text(value: Optional[str]) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def get_next_person_id() -> str:
    if supabase is None:
        return "P0001"
    response = (
        supabase.table("persons")
        .select("person_id")
        .order("person_id", desc=True)
        .limit(1)
        .execute()
    )
    if not response.data:
        return "P0001"
    last = response.data[0].get("person_id", "")
    match = re.search(r"(\d+)$", last)
    return f"P{int(match.group(1)) + 1:04d}" if match else "P0001"


def first_money_values(text: str) -> List[float]:
    values: List[float] = []
    patterns = [
        r"(?:INR|Rs\.?|₹)\s*([0-9,]+(?:\.\d+)?)",
        r"amount\s*[:=]\s*([0-9,]+(?:\.\d+)?)",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.I):
            try:
                values.append(float(match.group(1).replace(",", "")))
            except ValueError:
                continue
    return values


def count_numeric(patterns: List[str], text: str) -> int:
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.I | re.S)
        if match:
            try:
                return int(match.group(1))
            except (TypeError, ValueError):
                continue
    return 0


def source_activity(source_type: str, text: str) -> Dict[str, float]:
    source = source_type.upper()

    calls = count_numeric(
        [
            r"(?:phone\s+)?calls?\s*[:=]\s*(\d+)",
            r"(\d+)\s+(?:phone\s+)?calls?",
        ],
        text,
    )
    transactions = count_numeric(
        [
            r"transactions?\s*[:=]\s*(\d+)",
            r"(\d+)\s+transactions?",
        ],
        text,
    )
    meetings = count_numeric(
        [
            r"meetings?\s*[:=]\s*(\d+)",
            r"(\d+)\s+meetings?",
        ],
        text,
    )

    if source == "CDR" and calls == 0:
        # Count explicit CDR rows when the source has caller/receiver records.
        calls = len(re.findall(r"caller\s*:", text, flags=re.I))
        if calls == 0 and text.strip():
            calls = 1

    if source == "FINANCIAL" and transactions == 0:
        transactions = len(re.findall(r"transaction\s*\d+", text, flags=re.I))
        if transactions == 0 and text.strip():
            transactions = 1

    if source == "SURVEILLANCE" and meetings == 0:
        meetings = len(
            re.findall(r"(?:\d{1,2}:\d{2}|meeting|observed meeting)", text, flags=re.I)
        )
        meetings = min(meetings, 20)
        if meetings == 0 and text.strip():
            meetings = 1

    money = first_money_values(text)
    total_amount = sum(money) if source == "FINANCIAL" else max(money) if money else 0.0

    duration_values = [
        int(x)
        for x in re.findall(
            r"duration\s*[:=]\s*(\d+)\s*(?:seconds?|sec)?", text, flags=re.I
        )
    ]
    total_duration = sum(duration_values)

    return {
        "calls": float(calls),
        "duration": float(total_duration),
        "transactions": float(transactions),
        "amount": float(total_amount),
        "meetings": float(meetings),
    }


# -----------------------------------------------------------------------------
# ML feature generation
# -----------------------------------------------------------------------------


def relationship_features(record: Dict[str, Any]) -> List[float]:
    calls = float(record.get("phone_call_count") or record.get("calls") or 0)
    duration = float(
        record.get("total_call_duration_sec") or record.get("duration") or 0
    )
    txns = float(record.get("transaction_count") or record.get("transactions") or 0)
    amount = float(record.get("total_transaction_amount") or record.get("amount") or 0)
    meetings = float(record.get("meeting_count") or record.get("meetings") or 0)
    co = float(record.get("co_occurrences") or 0)
    source_diversity = float(record.get("source_diversity") or 0)

    return [
        math.log1p(calls),
        math.log1p(duration),
        math.log1p(txns),
        math.log1p(amount),
        math.log1p(meetings),
        math.log1p(co),
        source_diversity,
        float(record.get("shared_phone") or 0),
        float(record.get("shared_vehicle") or 0),
        float(record.get("shared_org") or 0),
        float(record.get("shared_location") or 0),
    ]


def predict_relationship(record: Dict[str, Any]) -> float:
    """
    Calculate an evidence-grounded potential relationship score.

    The score is NOT a probability of guilt. It measures how strongly the
    submitted investigation evidence supports a relationship between the two
    people.

    Components:
      - 75% explainable live-evidence strength
      - 25% learned model signal

    The live-evidence component rewards direct person-to-person records,
    repeated activity, and independent source corroboration. A narrative
    mention by itself therefore does not become a high-confidence relationship,
    while multiple calls + transactions + meetings produce a substantially
    stronger score.
    """
    global RELATIONSHIP_MODEL

    values = relationship_features(record)
    model_score = None

    if RELATIONSHIP_MODEL is None:
        RELATIONSHIP_MODEL = load_model(RELATIONSHIP_MODEL_PATH)

    if RELATIONSHIP_MODEL is not None:
        try:
            model_score = float(
                RELATIONSHIP_MODEL.predict_proba([values])[0][1]
            )
        except Exception as exc:
            print("Relationship model inference failed:", exc)
            model_score = None

    calls = float(record.get("calls") or 0)
    duration = float(record.get("duration") or 0)
    txns = float(record.get("transactions") or 0)
    amount = float(record.get("amount") or 0)
    meetings = float(record.get("meetings") or 0)
    diversity = float(record.get("source_diversity") or 0)
    co = float(record.get("co_occurrences") or 0)

    # ---------------------------------------------------------
    # Explainable evidence score: 0..100
    # ---------------------------------------------------------
    evidence = 0.0

    # Direct communication evidence.
    if calls > 0:
        evidence += 22.0
        evidence += min(calls, 8.0) * 2.2

        # Longer cumulative communication strengthens the relationship
        # evidence, but with diminishing returns.
        evidence += min(duration / 900.0, 4.0) * 1.5

    # Direct financial person -> person evidence.
    if txns > 0:
        evidence += 24.0
        evidence += min(txns, 5.0) * 2.5
        evidence += min(amount / 100000.0, 3.0) * 2.0

    # Direct meeting / observation evidence.
    if meetings > 0:
        evidence += 22.0
        evidence += min(meetings, 4.0) * 4.0

    # Explicit cross-source corroboration.
    evidence += min(diversity, 4.0) * 5.0

    # Explicit person co-occurrence in relationship-bearing records.
    evidence += min(co, 4.0) * 2.5

    # Shared identifiers are supporting evidence, not relationship proof.
    if record.get("shared_phone"):
        evidence += 8.0
    if record.get("shared_vehicle"):
        evidence += 5.0
    if record.get("shared_org"):
        evidence += 4.0
    if record.get("shared_location"):
        evidence += 4.0

    evidence_score = max(
        0.0,
        min(100.0, evidence),
    ) / 100.0

    # ---------------------------------------------------------
    # Combine the learned model with the evidence score.
    # The model is deliberately secondary because the live investigation
    # can contain evidence distributions that differ from synthetic training.
    # ---------------------------------------------------------
    if model_score is None:
        final_score = evidence_score
    else:
        final_score = (
            0.75 * evidence_score
            + 0.25 * model_score
        )

    return float(
        max(
            0.0,
            min(1.0, final_score),
        )
    )


def anomaly_result(record: Dict[str, Any]) -> Dict[str, Any]:
    global ANOMALY_MODEL
    values = relationship_features(record)
    anomaly_score = None
    is_anomaly = False

    if ANOMALY_MODEL is None:
        ANOMALY_MODEL = load_model(ANOMALY_MODEL_PATH)
    if ANOMALY_MODEL is not None:
        try:
            decision = float(ANOMALY_MODEL.decision_function([values])[0])
            prediction = int(ANOMALY_MODEL.predict([values])[0])
            anomaly_score = -decision
            is_anomaly = prediction == -1
        except Exception as exc:
            print("Anomaly model inference failed:", exc)

    reasons: List[str] = []
    if float(record.get("calls") or 0) >= 8:
        reasons.append("High communication frequency")
    if float(record.get("transactions") or 0) >= 3:
        reasons.append("Repeated financial activity")
    if float(record.get("amount") or 0) >= 100000:
        reasons.append("High aggregate transaction value")
    if float(record.get("meetings") or 0) >= 2:
        reasons.append("Repeated meetings")
    if float(record.get("source_diversity") or 0) >= 3:
        reasons.append("Evidence spans multiple intelligence sources")
    if any(
        record.get(key)
        for key in ["shared_phone", "shared_vehicle", "shared_org", "shared_location"]
    ):
        reasons.append("Shared identifying or contextual attribute")

    return {
        "is_anomaly": bool(is_anomaly or len(reasons) >= 3),
        "anomaly_score": anomaly_score,
        "reasons": reasons,
    }


def relationship_reason(record: Dict[str, Any]) -> str:
    reasons: List[str] = []
    if record.get("shared_phone"):
        reasons.append("shared phone evidence")
    if record.get("shared_vehicle"):
        reasons.append("shared vehicle evidence")
    if record.get("shared_org"):
        reasons.append("shared organization evidence")
    if record.get("shared_location"):
        reasons.append("shared location evidence")
    if record.get("co_occurrences"):
        reasons.append(
            f"co-occurrence in {int(record['co_occurrences'])} source record(s)"
        )
    if record.get("calls"):
        duration = int(record.get("duration") or 0)
        if duration:
            reasons.append(
                f"{int(record['calls'])} call signal(s) totaling {duration} seconds"
            )
        else:
            reasons.append(f"{int(record['calls'])} call signal(s)")
    if record.get("transactions"):
        amount = float(record.get("amount") or 0)
        reasons.append(
            f"{int(record['transactions'])} transaction signal(s) totaling ₹{amount:,.2f}"
            if amount
            else f"{int(record['transactions'])} transaction signal(s)"
        )
    if record.get("meetings"):
        reasons.append(f"{int(record['meetings'])} meeting signal(s)")
    if record.get("source_diversity"):
        reasons.append(
            f"evidence across {int(record['source_diversity'])} source type(s)"
        )

    return (
        "Candidate link generated from "
        + ", ".join(reasons or ["shared investigative context"])
        + "."
    )


# -----------------------------------------------------------------------------
# Live-investigation graph construction
# -----------------------------------------------------------------------------


PERSON_FALSE_POSITIVE = {
    "age", "status", "record", "record 1", "record 2", "record 3",
    "record 4", "record 5", "record 6", "record 7", "record 8",
    "cyber crime", "cyber crime unit", "criminal history",
    "criminal history database", "police", "police report",
    "police reports", "investigation", "investigation report",
    "investigators", "investigator", "financial fraud", "fraud",
    "fraud facilitation", "to account", "from account",
    "to person", "from person", "caller", "receiver", "account",
    "amount", "date", "time", "location", "vehicle", "organization",
    "company", "profile", "public profile", "source", "status",
    "completed", "under investigation", "under review", "none",
}

RELATIONSHIP_CUES = (
    "met", "meet", "meeting", "meetings", "called", "call", "contacted",
    "contact", "communication", "communicated", "spoke", "talked",
    "messaged", "message", "interaction", "interacted", "together",
    "partner", "friend", "family", "brother", "sister", "father",
    "mother", "spouse", "relative", "colleague", "associate",
    "associated", "transferred", "transfer", "transaction", "paid",
    "payment", "sent", "received", "observed", "seen", "travelled",
    "traveling", "travelling", "shared", "linked", "connected",
    "arrived", "departed",
)

def clean_person_name(value: str) -> str | None:
    value = re.sub(r"\s+", " ", str(value or "")).strip(" ,.;:-")
    if not value:
        return None

    normalized = normalize_text(value)

    if normalized in PERSON_FALSE_POSITIVE:
        return None

    # A genuine person name in our investigation graph should contain at least
    # two word-like tokens. This removes NER mistakes such as "K", "Status",
    # "To Account", and organization/category labels.
    tokens = value.split()

    if len(tokens) < 2:
        return None

    if len(tokens) > 5:
        return None

    if any(char.isdigit() for char in value):
        return None

    if any(
        token.lower().rstrip(":,.;")
        in PERSON_FALSE_POSITIVE
        for token in tokens
    ):
        return None

    if all(
        not re.search(r"[A-Za-zÀ-ÿ]", token)
        for token in tokens
    ):
        return None

    # Don't accept strings that are obviously field/category descriptions.
    category_words = {
        "account", "amount", "status", "crime", "record", "case",
        "reference", "date", "time", "duration", "location",
        "police", "report", "unit", "database", "profile",
    }
    if sum(token.lower().strip(":,.") in category_words for token in tokens) >= 1:
        return None

    return value


def extract_valid_people(
    extracted_people: list[str],
) -> list[str]:
    result = []
    seen = set()

    for person in extracted_people or []:
        cleaned = clean_person_name(person)
        if not cleaned:
            continue

        key = normalize_text(cleaned)
        if key in seen:
            continue

        seen.add(key)
        result.append(cleaned)

    return result


def extract_people_from_source_text(
    text: str,
    person_profiles: Dict[str, Dict[str, Any]],
) -> list[str]:
    """
    Resolve only already-known people from this investigation. This is used
    after entity extraction so the graph cannot accidentally promote arbitrary
    entities into people.
    """
    found = []
    for key, profile in person_profiles.items():
        name = profile["name"]
        if re.search(
            rf"\b{re.escape(name)}\b",
            text,
            flags=re.I,
        ):
            found.append(key)
    return sorted(set(found), key=lambda key: text.lower().find(
        person_profiles[key]["name"].lower()
    ))


def make_person_profile(
    name: str,
    sources: List[Dict[str, Any]],
) -> Dict[str, Any]:
    profile = {
        "temp_id": "",
        "name": name,
        "age": None,
        "location": None,
        "phone_num": None,
        "vehicle_num": None,
        "org": None,
        "bank_account": None,
        "crime_recorded": None,
        "fir_language": None,
        "source_types": set(),
    }

    def sentence_contexts(text: str) -> list[str]:
        return [
            item.strip()
            for item in re.split(r"(?<=[.!?])\s+|\n+", text)
            if item.strip()
            and re.search(
                rf"\b{re.escape(name)}\b",
                item,
                flags=re.I,
            )
        ]

    for source in sources:
        entities = source["entities"]
        text = source["content"]
        source_type = source["source_type"].upper()
        profile["source_types"].add(source_type)

        for context in sentence_contexts(text):
            if not profile["phone_num"]:
                match = re.search(
                    r"(?<!\d)((?:\+91[- ]?)?[6-9]\d{9})(?!\d)",
                    context,
                )
                if match:
                    profile["phone_num"] = clean_phone(match.group(1))

            if not profile["vehicle_num"]:
                match = re.search(
                    r"\b((?:DL|HR|UP|PB)[- ]?\d{1,2}[- ]?[A-Z]{1,3}[- ]?\d{3,4})\b",
                    context,
                    flags=re.I,
                )
                if match:
                    profile["vehicle_num"] = match.group(1)

            if not profile["age"]:
                match = re.search(
                    r"\bage\s*[:=]?\s*(\d{1,3})",
                    context,
                    flags=re.I,
                )
                if match:
                    profile["age"] = int(match.group(1))

            if not profile["org"]:
                match = re.search(
                    r"(?:associated with|works at|works for|organization|company)\s*"
                    r"[:=]?\s*([A-Z][A-Za-z&.'-]*(?:\s+[A-Z][A-Za-z&.'-]*){0,6})",
                    context,
                    flags=re.I,
                )
                if match:
                    candidate = match.group(1).strip(" ,.;:")
                    if len(candidate) > 2:
                        profile["org"] = candidate

            if not profile["location"]:
                match = re.search(
                    r"(?:near|at|in|from|location)\s*[:=]?\s*"
                    r"([A-Z][A-Za-z0-9 ,.'-]{2,60})",
                    context,
                    flags=re.I,
                )
                if match:
                    candidate = match.group(1).strip(" ,.;:")
                    if len(candidate) > 2:
                        profile["location"] = candidate

            if not profile["bank_account"]:
                match = re.search(
                    r"\b(?:account|bank account)\s*[:=]?\s*"
                    r"(X{2,}\d{2,}|(?:XX)?\d{6,18})\b",
                    context,
                    flags=re.I,
                )
                if match:
                    profile["bank_account"] = match.group(1)

        # Safe fallback if the source contains exactly one valid person.
        valid_people = extract_valid_people(entities.get("PERSON", []))
        if len(valid_people) == 1 and valid_people[0].lower() == name.lower():
            if not profile["phone_num"] and entities.get("PHONE"):
                profile["phone_num"] = clean_phone(entities["PHONE"][0])
            if not profile["vehicle_num"] and entities.get("VEHICLE"):
                profile["vehicle_num"] = entities["VEHICLE"][0]
            if not profile["org"] and entities.get("ORG"):
                profile["org"] = entities["ORG"][0]
            if not profile["location"] and entities.get("GPE"):
                profile["location"] = entities["GPE"][0]
            if not profile["bank_account"] and entities.get("BANK"):
                profile["bank_account"] = entities["BANK"][0]

        if (
            source_type in {"CRIMINAL_HISTORY", "FIR"}
            and not profile["crime_recorded"]
        ):
            match = re.search(
                rf"\b{re.escape(name)}\b[^.\n]{{0,180}}?"
                r"(?:recorded\s+categories|crime|charges?|case\s+references?)"
                r"\s*[:=]?\s*([^\.\n]+)",
                text,
                flags=re.I,
            )
            if match:
                profile["crime_recorded"] = match.group(1).strip()

        if source_type == "FIR" and not profile["fir_language"]:
            profile["fir_language"] = source.get("language", "en")

    return profile


def candidate_key(a: str, b: str) -> Tuple[str, str]:
    return tuple(sorted((a, b)))


def build_live_candidates(
    sources: List[Dict[str, Any]],
    person_profiles: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Build ONLY evidence-backed person-to-person relationships.

    There is no all-to-all combination across a complete document.
    """
    candidates: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def get_candidate(a: str, b: str) -> Dict[str, Any]:
        key = candidate_key(a, b)
        return candidates.setdefault(
            key,
            {
                "person_a_key": key[0],
                "person_b_key": key[1],
                "phone_call_count": 0,
                "total_call_duration_sec": 0,
                "transaction_count": 0,
                "total_transaction_amount": 0,
                "meeting_count": 0,
                "co_occurrences": 0,
                "source_types": set(),
                "shared_phone": 0,
                "shared_vehicle": 0,
                "shared_org": 0,
                "shared_location": 0,
            },
        )

    def add_pair(
        a_key: str,
        b_key: str,
        source_type: str,
        calls: int = 0,
        duration: int = 0,
        transactions: int = 0,
        amount: float = 0.0,
        meetings: int = 0,
    ):
        if not a_key or not b_key or a_key == b_key:
            return

        record = get_candidate(a_key, b_key)
        record["co_occurrences"] += 1
        record["source_types"].add(source_type)
        record["phone_call_count"] += calls
        record["total_call_duration_sec"] += duration
        record["transaction_count"] += transactions
        record["total_transaction_amount"] += amount
        record["meeting_count"] += meetings

    # --------------------------------------------------------------
    # Narrative sources: pair names ONLY when they are explicitly
    # connected in the same sentence/record.
    # --------------------------------------------------------------
    narrative_sources = {
        "FIR",
        "POLICE_REPORT",
        "SURVEILLANCE",
        "SOCIAL_MEDIA",
        "CRIMINAL_HISTORY",
    }

    for source in sources:
        source_type = source["source_type"].upper()
        content = source["content"]

        if source_type in narrative_sources:
            records = [
                item.strip()
                for item in re.split(r"(?<=[.!?])\s+|\n+", content)
                if item.strip()
            ]

            for record_text in records:
                mentioned = extract_people_from_source_text(
                    record_text,
                    person_profiles,
                )

                if len(mentioned) < 2:
                    continue

                # Only relationship-bearing records generate links.
                lower = record_text.lower()
                if not any(
                    cue in lower for cue in RELATIONSHIP_CUES
                ):
                    continue

                if len(mentioned) == 2:
                    a_key, b_key = mentioned
                    add_pair(
                        a_key,
                        b_key,
                        source_type,
                        meetings=(
                            1
                            if source_type == "SURVEILLANCE"
                            and any(
                                cue in lower
                                for cue in (
                                    "meet", "meeting", "observed",
                                    "seen together",
                                )
                            )
                            else 0
                        ),
                    )
                else:
                    # With >2 people in one sentence, do NOT make all pairs.
                    # Link only the two people closest around the relationship
                    # cue. This avoids N choose 2 explosions.
                    cue_positions = [
                        lower.find(cue)
                        for cue in RELATIONSHIP_CUES
                        if lower.find(cue) >= 0
                    ]
                    cue_pos = (
                        min(cue_positions)
                        if cue_positions
                        else len(record_text) // 2
                    )

                    before = [
                        key
                        for key in mentioned
                        if record_text.lower().find(
                            person_profiles[key]["name"].lower()
                        ) < cue_pos
                    ]
                    after = [
                        key
                        for key in mentioned
                        if record_text.lower().find(
                            person_profiles[key]["name"].lower()
                        ) > cue_pos
                    ]

                    if before and after:
                        add_pair(
                            before[-1],
                            after[0],
                            source_type,
                            meetings=(
                                1
                                if source_type == "SURVEILLANCE"
                                else 0
                            ),
                        )

        # ----------------------------------------------------------
        # CDR: ONLY explicit caller -> receiver phone pair.
        # ----------------------------------------------------------
        elif source_type == "CDR":
            people_by_phone = {
                clean_phone(profile.get("phone_num")): key
                for key, profile in person_profiles.items()
                if profile.get("phone_num")
            }

            blocks = [
                item.strip()
                for item in re.split(
                    r"(?=Record\s+\d+)",
                    content,
                    flags=re.I,
                )
                if item.strip()
            ]

            for block in blocks:
                caller_match = re.search(
                    r"Caller\s*:\s*((?:\+91[- ]?)?[6-9]\d{9})",
                    block,
                    flags=re.I,
                )
                receiver_match = re.search(
                    r"Receiver\s*:\s*((?:\+91[- ]?)?[6-9]\d{9})",
                    block,
                    flags=re.I,
                )

                if not caller_match or not receiver_match:
                    continue

                caller = clean_phone(caller_match.group(1))
                receiver = clean_phone(receiver_match.group(1))

                a_key = people_by_phone.get(caller)
                b_key = people_by_phone.get(receiver)

                if not a_key or not b_key or a_key == b_key:
                    continue

                duration_match = re.search(
                    r"Duration\s*:\s*(\d+)",
                    block,
                    flags=re.I,
                )

                add_pair(
                    a_key,
                    b_key,
                    "CDR",
                    calls=1,
                    duration=(
                        int(duration_match.group(1))
                        if duration_match
                        else 0
                    ),
                )

        # ----------------------------------------------------------
        # Financial: ONLY explicit From Person -> To Person.
        # ----------------------------------------------------------
        elif source_type == "FINANCIAL":
            transactions = [
                item.strip()
                for item in re.split(
                    r"(?=Transaction\s+\d+)",
                    content,
                    flags=re.I,
                )
                if item.strip()
            ]

            for chunk in transactions:
                from_match = re.search(
                    r"From Person\s*:\s*([^\n]+)",
                    chunk,
                    flags=re.I,
                )
                to_match = re.search(
                    r"To Person\s*:\s*([^\n]+)",
                    chunk,
                    flags=re.I,
                )
                amount_match = re.search(
                    r"Amount\s*:\s*(?:INR|Rs\.?|₹)?\s*([0-9,]+(?:\.\d+)?)",
                    chunk,
                    flags=re.I,
                )

                if not from_match or not to_match:
                    continue

                a_key = normalize_text(from_match.group(1))
                b_key = normalize_text(to_match.group(1))

                if a_key not in person_profiles or b_key not in person_profiles:
                    continue

                add_pair(
                    a_key,
                    b_key,
                    "FINANCIAL",
                    transactions=1,
                    amount=(
                        float(
                            amount_match.group(1).replace(",", "")
                        )
                        if amount_match
                        else 0.0
                    ),
                )

    results: List[Dict[str, Any]] = []

    for record in candidates.values():
        record["source_diversity"] = len(
            record.pop("source_types")
        )
        record["calls"] = record["phone_call_count"]
        record["duration"] = record["total_call_duration_sec"]
        record["transactions"] = record["transaction_count"]
        record["amount"] = record["total_transaction_amount"]
        record["meetings"] = record["meeting_count"]

        record["model_confidence"] = predict_relationship(record)

        # Human-readable score basis for the investigator.
        score_factors = []

        if int(record.get("calls") or 0) > 0:
            score_factors.append(
                f"{int(record['calls'])} phone call(s)"
            )

        if int(record.get("transactions") or 0) > 0:
            score_factors.append(
                f"{int(record['transactions'])} financial transaction(s)"
            )

        if float(record.get("amount") or 0) > 0:
            score_factors.append(
                f"₹{float(record['amount']):,.0f} total transaction value"
            )

        if int(record.get("meetings") or 0) > 0:
            score_factors.append(
                f"{int(record['meetings'])} meeting/observation record(s)"
            )

        if int(record.get("source_diversity") or 0) > 1:
            score_factors.append(
                f"{int(record['source_diversity'])} independent source type(s)"
            )

        if record.get("shared_phone"):
            score_factors.append("shared phone identifier")

        if record.get("shared_vehicle"):
            score_factors.append("shared vehicle identifier")

        if record.get("shared_org"):
            score_factors.append("shared organization")

        if record.get("shared_location"):
            score_factors.append("shared location")

        record["score_basis"] = score_factors
        record["reason"] = relationship_reason(record)

        calls = int(record.get("calls") or 0)
        txns = int(record.get("transactions") or 0)
        meetings = int(record.get("meetings") or 0)

        if calls >= 3 and txns >= 1:
            record["relationship_type"] = (
                "Communication & Financial Association"
            )
        elif meetings >= 1 and txns >= 1:
            record["relationship_type"] = (
                "Meeting & Financial Association"
            )
        elif meetings >= 2:
            record["relationship_type"] = (
                "Repeated Meeting Association"
            )
        elif txns >= 1:
            record["relationship_type"] = "Financial Association"
        elif calls >= 1:
            record["relationship_type"] = "Communication Association"
        elif record.get("source_diversity", 0) >= 2:
            record["relationship_type"] = "Multi-source Association"
        else:
            record["relationship_type"] = (
                "Evidence-linked Association"
            )

        anomaly = anomaly_result(record)
        record["suspicious"] = anomaly["is_anomaly"]
        record["anomaly_score"] = anomaly["anomaly_score"]
        record["suspicious_reasons"] = anomaly["reasons"]

        results.append(record)

    results.sort(
        key=lambda item: item["model_confidence"],
        reverse=True,
    )
    return results


def build_live_graph(
    investigation_id: str,
    person_profiles: Dict[str, Dict[str, Any]],
    candidates: List[Dict[str, Any]],
) -> Dict[str, Any]:

    connected_keys = set()

    for record in candidates:
        connected_keys.add(record["person_a_key"])
        connected_keys.add(record["person_b_key"])

    investigation_prefix = re.sub(
        r"[^A-Za-z0-9]",
        "",
        investigation_id,
    )[:12].upper()

    key_to_id: Dict[str, str] = {}

    for index, key in enumerate(
        sorted(connected_keys),
        start=1,
    ):
        key_to_id[key] = (
            f"LIVE-{investigation_prefix}-{index:04d}"
        )

    nodes = []

    for key in sorted(connected_keys):
        profile = person_profiles[key]

        nodes.append(
            {
                "id": key_to_id[key],
                "name": profile["name"],
                "type": "PERSON",
                "is_center": False,
                "age": profile.get("age"),
                "location": profile.get("location"),
                "phone_num": profile.get("phone_num"),
                "vehicle_num": profile.get("vehicle_num"),
                "org": profile.get("org"),
                "bank_account": profile.get("bank_account"),
                "crime_recorded": profile.get("crime_recorded"),
                "fir_language": profile.get("fir_language"),
                "source_types": sorted(
                    profile.get("source_types") or []
                ),
            }
        )

    links = []

    for record in candidates:
        source = key_to_id.get(record["person_a_key"])
        target = key_to_id.get(record["person_b_key"])

        if not source or not target:
            continue

        links.append(
            {
                "source": source,
                "target": target,
                "relationship_type": record["relationship_type"],
                "relationship_description": (
                    f"{record['reason']} This is an analytical lead "
                    "generated only from evidence supplied for this "
                    "investigation."
                ),
                "confidence": float(record.get("model_confidence") or 0.0),
                "reason": record["reason"],
                "score_basis": record.get("score_basis", []),
                "calls": record["phone_call_count"],
                "total_call_duration_sec": record[
                    "total_call_duration_sec"
                ],
                "transactions": record["transaction_count"],
                "meetings": record["meeting_count"],
                "total_transaction_amount": record[
                    "total_transaction_amount"
                ],
                "suspicious": record["suspicious"],
                "anomaly_score": record["anomaly_score"],
                "suspicious_reasons": record["suspicious_reasons"],
            }
        )

    return {
        "nodes": nodes,
        "links": links,
    }


def live_graph_analytics(graph_data: Dict[str, Any]) -> Dict[str, Any]:
    import networkx as nx

    graph = nx.Graph()
    names = {}
    for node in graph_data["nodes"]:
        graph.add_node(node["id"])
        names[node["id"]] = node["name"]
    for link in graph_data["links"]:
        graph.add_edge(
            link["source"],
            link["target"],
            weight=float(link.get("confidence") or 0.0),
        )

    if not graph.nodes:
        return {"influential_persons": [], "community_count": 0}

    degree = nx.degree_centrality(graph)
    betweenness = nx.betweenness_centrality(graph, normalized=True)
    pagerank = (
        nx.pagerank(graph, weight="weight")
        if len(graph) > 1
        else {next(iter(graph.nodes)): 1.0}
    )

    influential = []
    for pid in graph.nodes:
        score = (
            0.35 * degree.get(pid, 0)
            + 0.35 * betweenness.get(pid, 0)
            + 0.30 * pagerank.get(pid, 0)
        )
        influential.append(
            {
                "person_id": pid,
                "name": names.get(pid, pid),
                "influence_score": round(float(score), 4),
                "degree_centrality": round(float(degree.get(pid, 0)), 4),
                "betweenness_centrality": round(float(betweenness.get(pid, 0)), 4),
                "pagerank": round(float(pagerank.get(pid, 0)), 4),
            }
        )

    influential.sort(key=lambda item: item["influence_score"], reverse=True)
    return {
        "influential_persons": influential[:10],
        "community_count": nx.number_connected_components(graph),
    }


# -----------------------------------------------------------------------------
# Persistence helpers — current investigation only
# -----------------------------------------------------------------------------


def persist_people(
    investigation_id: str,
    graph_data: Dict[str, Any],
    source_documents: List[Dict[str, Any]],
) -> None:
    """
    Persist only people generated from the current investigation's submitted
    evidence. source_type is stored inside each item's document object.
    """
    if supabase is None:
        return

    document_ids: Dict[str, str] = {}

    for item in source_documents:
        document = item.get("document") or {}
        source_type = document.get("source_type")
        document_id = document.get("id")

        if source_type and document_id:
            document_ids[source_type] = document_id

    for node in graph_data.get("nodes", []):
        payload = {
            "person_id": node["id"],
            "investigation_id": investigation_id,
            "name": node["name"],
            "age": node.get("age"),
            "location": node.get("location"),
            "phone_num": node.get("phone_num"),
            "vehicle_num": node.get("vehicle_num"),
            "org": node.get("org"),
            "bank_account": node.get("bank_account"),
            "crime_recorded": (
                node.get("crime_recorded")
                or "Source-linked subject"
            ),
            "fir_language": node.get("fir_language"),
            "source_document_id": document_ids.get("FIR"),
        }

        payload = {
            key: value
            for key, value in payload.items()
            if value is not None
        }

        try:
            existing = (
                supabase
                .table("persons")
                .select("id")
                .eq("investigation_id", investigation_id)
                .eq("person_id", node["id"])
                .limit(1)
                .execute()
            )

            if existing.data:
                (
                    supabase
                    .table("persons")
                    .update(payload)
                    .eq("id", existing.data[0]["id"])
                    .execute()
                )
            else:
                supabase.table("persons").insert(payload).execute()

        except Exception as exc:
            print(
                f"Person persistence failed for "
                f"{node.get('name', 'Unknown')}: {exc}"
            )
            raise HTTPException(
                status_code=500,
                detail=(
                    "Unable to save extracted person "
                    f"{node.get('name', 'Unknown')}: {exc}"
                ),
            )


def persist_relationships(
    investigation_id: str,
    graph_data: Dict[str, Any],
) -> None:
    """
    Persist generated relationships for this investigation only.
    Retries without optional anomaly fields for an older schema.
    """
    if supabase is None:
        return

    try:
        (
            supabase
            .table("person_relationships")
            .delete()
            .eq("investigation_id", investigation_id)
            .execute()
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to reset investigation relationships: {exc}",
        )

    node_names = {
        node["id"]: node["name"]
        for node in graph_data.get("nodes", [])
    }

    investigation_token = re.sub(
        r"[^A-Za-z0-9]",
        "",
        investigation_id,
    )[:12].upper()

    for index, link in enumerate(
        graph_data.get("links", []),
        start=1,
    ):
        payload = {
            "relationship_id": f"LIVE-{investigation_token}-{index:04d}",
            "investigation_id": investigation_id,
            "person_a_id": link["source"],
            "person_a_name": node_names.get(
                link["source"],
                link["source"],
            ),
            "person_b_id": link["target"],
            "person_b_name": node_names.get(
                link["target"],
                link["target"],
            ),
            "phone_call_count": link.get("calls", 0),
            "total_call_duration_sec": link.get(
                "total_call_duration_sec",
                0,
            ),
            "transaction_count": link.get(
                "transactions",
                0,
            ),
            "total_transaction_amount": link.get(
                "total_transaction_amount",
                0,
            ),
            "meeting_count": link.get(
                "meetings",
                0,
            ),
            "relationship_label": 1,
            "ground_truth_confidence": None,
            "model_confidence": float(link.get("confidence") or 0.0),
            "relationship_type": (
                link.get("relationship_type")
                or "Evidence-linked Association"
            ),
            "relationship_description": link.get(
                "relationship_description"
            ),
            "reason": link.get("reason"),
            "suspicious": bool(link.get("suspicious")),
            "anomaly_score": link.get("anomaly_score"),
        }

        try:
            (
                supabase
                .table("person_relationships")
                .insert(payload)
                .execute()
            )
        except Exception as first_error:
            error_text = str(first_error).lower()

            missing_optional_column = (
                "suspicious" in error_text
                or "anomaly_score" in error_text
                or (
                    "column" in error_text
                    and "does not exist" in error_text
                )
            )

            if not missing_optional_column:
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "Unable to save generated relationship: "
                        f"{first_error}"
                    ),
                )

            legacy_payload = dict(payload)
            legacy_payload.pop("suspicious", None)
            legacy_payload.pop("anomaly_score", None)

            try:
                (
                    supabase
                    .table("person_relationships")
                    .insert(legacy_payload)
                    .execute()
                )
            except Exception as second_error:
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "Unable to save generated relationship. "
                        f"Initial error: {first_error}; "
                        f"Retry error: {second_error}"
                    ),
                )



# -----------------------------------------------------------------------------
# Core endpoints
# -----------------------------------------------------------------------------


@app.get("/health")
def health():
    return {
        "status": "ok",
        "supabase_configured": supabase is not None,
        "relationship_model_loaded": RELATIONSHIP_MODEL is not None,
        "anomaly_model_loaded": ANOMALY_MODEL is not None,
        "model_loading": "lazy_on_first_analysis",
        "analysis_mode": "live-submitted-evidence",
    }


@app.post("/api/investigations")
def create_investigation(
    body: InvestigationCreate,
    authorization: Optional[str] = Header(None),
):
    user_id = require_user(authorization)
    result = (
        supabase.table("investigations")
        .insert(
            {
                "title": body.title.strip(),
                "description": body.description,
                "created_by": user_id,
                "status": "active",
            }
        )
        .execute()
    )
    if not result.data:
        raise HTTPException(500, "Unable to create investigation")
    return result.data[0]


@app.post("/api/investigations/{investigation_id}/close")
def close_investigation(
    investigation_id: str,
    authorization: Optional[str] = Header(None),
):
    require_user(authorization)
    result = (
        supabase.table("investigations")
        .update({"status": "closed", "closed_at": utc_now()})
        .eq("id", investigation_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(404, "Investigation not found")
    return result.data[0]


@app.get("/api/investigations/{investigation_id}/sources")
def get_investigation_sources(
    investigation_id: str,
    authorization: Optional[str] = Header(None),
):
    user_id = require_user(authorization)

    investigation = (
        supabase.table("investigations")
        .select("id, created_by")
        .eq("id", investigation_id)
        .maybe_single()
        .execute()
    )

    if not investigation.data:
        raise HTTPException(404, "Investigation not found")

    if investigation.data["created_by"] != user_id:
        raise HTTPException(403, "You do not have access to this investigation")

    result = (
        supabase.table("investigation_sources")
        .select("*")
        .eq("investigation_id", investigation_id)
        .order("source_type")
        .execute()
    )

    # Return a stable object shape for the frontend.
    return {
        "investigation_id": investigation_id,
        "sources": result.data or [],
    }


@app.put("/api/investigations/{investigation_id}/sources")
def save_investigation_sources(
    investigation_id: str,
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
):
    user_id = require_user(authorization)

    investigation = (
        supabase.table("investigations")
        .select("id, created_by")
        .eq("id", investigation_id)
        .maybe_single()
        .execute()
    )

    if not investigation.data:
        raise HTTPException(404, "Investigation not found")

    if investigation.data["created_by"] != user_id:
        raise HTTPException(403, "You do not have access to this investigation")

    sources = normalize_source_payload(body.get("sources"))
    saved = []

    for source in sources:
        source_type = source.source_type.strip().upper()
        if not source_type:
            continue

        payload = {
            "investigation_id": investigation_id,
            "source_type": source_type,
            "title": source.title or source_type.title(),
            "content": source.content or "",
            "language": source.language or "en",
            "updated_at": utc_now(),
        }

        try:
            existing = (
                supabase.table("investigation_sources")
                .select("id")
                .eq("investigation_id", investigation_id)
                .eq("source_type", source_type)
                .limit(1)
                .execute()
            )

            if existing.data:
                result = (
                    supabase.table("investigation_sources")
                    .update(payload)
                    .eq("id", existing.data[0]["id"])
                    .execute()
                )
            else:
                payload["created_at"] = utc_now()
                result = (
                    supabase.table("investigation_sources")
                    .insert(payload)
                    .execute()
                )

            if result.data:
                saved.append(result.data[0])

        except Exception as exc:
            print(f"Source persistence failed for {source_type}: {exc}")
            raise HTTPException(
                status_code=500,
                detail=f"Unable to save {source_type} source: {exc}",
            )

    return {
        "investigation_id": investigation_id,
        "sources": saved,
        "saved_count": len(saved),
    }


def normalize_source_payload(raw_sources: Any) -> List[SourceInput]:
    """
    Normalize source payloads so a harmless empty/null field from the React
    form does not turn the entire analysis request into a FastAPI 422.
    Invalid/empty source rows are ignored; at least one non-empty source is
    still required by analyze_sources().
    """
    if raw_sources is None:
        return []

    if isinstance(raw_sources, dict):
        raw_sources = raw_sources.get("sources", [])

    if not isinstance(raw_sources, list):
        return []

    normalized: List[SourceInput] = []

    for raw in raw_sources:
        if not isinstance(raw, dict):
            continue

        source_type = str(
            raw.get("source_type")
            or raw.get("type")
            or ""
        ).strip().upper()

        content = raw.get("content")
        if content is None:
            content = ""

        title = raw.get("title")
        language = raw.get("language") or "en"

        normalized.append(
            SourceInput(
                source_type=source_type,
                title=str(title) if title is not None else None,
                content=str(content),
                language=str(language),
            )
        )

    return normalized


def source_snapshot_hash(
    sources: List[Any],
) -> str:
    normalized = []

    for source in sources:
        normalized.append(
            {
                "source_type": str(source.source_type).strip().upper(),
                "title": source.title or "",
                "content": source.content or "",
                "language": source.language or "en",
            }
        )

    normalized.sort(key=lambda item: item["source_type"])
    return sha256_json(normalized)


@app.post("/api/investigations/{investigation_id}/analyze-sources")
def analyze_sources(
    investigation_id: str,
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
):
    user_id = require_user(authorization)

    sources = normalize_source_payload(body.get("sources"))

    if not sources:
        raise HTTPException(400, "Provide at least one intelligence source")

    if not any(source.content.strip() for source in sources):
        raise HTTPException(400, "Provide at least one non-empty intelligence source")

    # Persist raw inputs before running the analysis pipeline so the
    # investigator's work survives errors, sign-out, and re-login.
    save_investigation_sources(
        investigation_id,
        {
            "sources": [source.model_dump() for source in sources],
        },
        authorization,
    )

    current_source_hash = source_snapshot_hash(sources)

    context_documents: List[Dict[str, Any]] = []
    persisted_documents: List[Dict[str, Any]] = []
    entity_counts: Counter[str] = Counter()
    raw_person_names: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # IMPORTANT: analysis is performed exclusively from this request's
    # submitted source corpus. Training CSVs and pre-existing unrelated
    # investigation records are not read for graph construction.
    # ------------------------------------------------------------------
    for index, source in enumerate(sources):
        content = source.content.strip()
        if not content:
            continue

        entities = extract_entities(content)

        # PERSON from spaCy can occasionally contain a location, organization,
        # section heading, or another non-person phrase. A live investigation
        # graph must contain PERSON nodes only. Filter PERSON candidates against
        # the other entity classes before creating person profiles.
        gpe_values = {normalize_text(value) for value in entities.get("GPE", [])}
        org_values = {normalize_text(value) for value in entities.get("ORG", [])}
        for person_name in extract_valid_people(entities.get("PERSON", [])):
            key = normalize_text(person_name)
            if not key:
                continue

            # Reject exact matches and names containing an extracted location
            # or organization phrase, e.g. "Noida Sector 18".
            if any(
                entity and (key == entity or re.search(rf"\b{re.escape(entity)}\b", key))
                for entity in (gpe_values | org_values)
            ):
                continue

            raw_person_names[key] = person_name

        for label, values in entities.items():
            entity_counts[label] += len(values)

        title = source.title or f"{source.source_type.title()} {index + 1}"
        content_hash = sha256_json(
            {
                "content": content,
                "source_type": source.source_type,
                "title": title,
            }
        )
        row = {
            "investigation_id": investigation_id,
            "source_type": source.source_type.upper(),
            "title": title,
            "content": content,
            "language": source.language,
            "content_hash": content_hash,
            "extracted_entities": entities,
        }
        inserted = supabase.table("documents").insert(row).execute()
        document = inserted.data[0] if inserted.data else None

        context_documents.append(
            {
                "source_type": source.source_type.upper(),
                "title": title,
                "content": content,
                "language": source.language,
                "entities": entities,
                "document_id": document["id"] if document else None,
            }
        )
        persisted_documents.append({"document": document, "entities": entities})

    if not context_documents:
        raise HTTPException(
            400, "At least one non-empty intelligence source is required"
        )

    # Build all live person profiles from this submitted corpus only.
    person_profiles: Dict[str, Dict[str, Any]] = {}
    for key, display_name in raw_person_names.items():
        person_profiles[key] = make_person_profile(display_name, context_documents)

    candidates = build_live_candidates(context_documents, person_profiles)
    graph_data = build_live_graph(investigation_id, person_profiles, candidates)
    analytics = live_graph_analytics(graph_data)

    suspicious_patterns = [
        {
            "person_a_id": c["person_a_key"],
            "person_b_id": c["person_b_key"],
            "confidence": c["model_confidence"],
            "reasons": c["suspicious_reasons"],
            "anomaly_score": c["anomaly_score"],
        }
        for c in candidates
        if c["suspicious"]
    ]

    top_relationships = [
        {
            "person_a_id": c["person_a_key"],
            "person_b_id": c["person_b_key"],
            "confidence": c["model_confidence"],
            "reason": c["reason"],
            "relationship_type": c["relationship_type"],
            "source_diversity": c["source_diversity"],
            "calls": c["phone_call_count"],
            "transactions": c["transaction_count"],
            "meetings": c["meeting_count"],
            "total_transaction_amount": c["total_transaction_amount"],
        }
        for c in candidates[:10]
    ]

    # Persist only the records generated by this current investigation.
    persist_people(investigation_id, graph_data, persisted_documents)
    persist_relationships(investigation_id, graph_data)

    audit_payload = {
        "sources_processed": len(context_documents),
        "entities": dict(entity_counts),
        "candidate_links": len(candidates),
        "suspicious_links": len(suspicious_patterns),
        "analysis_mode": "submitted_evidence_only",
    }

    try:
        supabase.table("analysis_runs").insert(
            {
                "investigation_id": investigation_id,
                "actor_id": user_id,
                "sources_processed": len(context_documents),
                "entities_extracted": int(sum(entity_counts.values())),
                "candidate_links": len(candidates),
                "suspicious_links": len(suspicious_patterns),
                "summary": {
                    "entity_counts": dict(entity_counts),
                    "top_relationships": top_relationships,
                    "influential_persons": analytics.get("influential_persons", []),
                    "suspicious_patterns": suspicious_patterns[:20],
                    "community_count": analytics.get("community_count", 0),
                    "graph": graph_data,
                    "summary_text": (
                        f"Analysis completed from {len(context_documents)} "
                        f"submitted intelligence source(s), identifying "
                        f"{int(sum(entity_counts.values()))} extracted "
                        f"entities and {len(candidates)} evidence-backed "
                        f"candidate relationship(s)."
                    ),
                    "source_snapshot_hash": current_source_hash,
                    "analysis_mode": "submitted_evidence_only",
                },
            }
        ).execute()
    except Exception as exc:
        print("Analysis-run persistence warning:", exc)

    try:
        previous = ""
        prior = (
            supabase.table("audit_log")
            .select("event_hash")
            .eq("investigation_id", investigation_id)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        if prior.data:
            previous = prior.data[0]["event_hash"]
        event_hash = sha256_json({"payload": audit_payload, "previous_hash": previous})
        supabase.table("audit_log").insert(
            {
                "actor_id": user_id,
                "investigation_id": investigation_id,
                "action": "investigation_analysis",
                "object_type": "analysis_run",
                "object_id": investigation_id,
                "payload": audit_payload,
                "previous_hash": previous,
                "event_hash": event_hash,
            }
        ).execute()
    except Exception as exc:
        print("Audit persistence warning:", exc)

    # Return the graph generated from THIS request, so the frontend does not
    # need to query the 600-person training dataset or another investigation.
    return {
        "investigation_id": investigation_id,
        "analysis_mode": "submitted_evidence_only",
        "sources": [
            {
                "source_type": d["source_type"],
                "title": d["title"],
                "entity_count": sum(len(v) for v in d["entities"].values()),
                "document_id": d["document_id"],
            }
            for d in context_documents
        ],
        "documents": persisted_documents,
        "entity_counts": dict(entity_counts),
        "candidate_relationships": top_relationships,
        "suspicious_patterns": suspicious_patterns[:20],
        "influential_persons": analytics.get("influential_persons", []),
        "community_count": analytics.get("community_count", 0),
        "graph": graph_data,
        "message": "Analysis completed from submitted investigation evidence only. Scores are analytical leads, not proof of criminality.",
    }


@app.get("/api/investigations/{investigation_id}/analysis")
def investigation_analysis(
    investigation_id: str,
    authorization: Optional[str] = Header(None),
):
    require_user(authorization)

    persons = (
        supabase.table("persons")
        .select("*")
        .eq("investigation_id", investigation_id)
        .execute()
        .data
        or []
    )

    relationships = (
        supabase.table("person_relationships")
        .select("*")
        .eq("investigation_id", investigation_id)
        .execute()
        .data
        or []
    )

    graph_data = {
        "nodes": [
            {
                "id": p["person_id"],
                "name": p["name"],
                "type": "PERSON",
                "is_center": False,
                "age": p.get("age"),
                "location": p.get("location"),
                "phone_num": p.get("phone_num"),
                "vehicle_num": p.get("vehicle_num"),
                "org": p.get("org"),
                "bank_account": p.get("bank_account"),
                "crime_recorded": p.get("crime_recorded"),
                "fir_language": p.get("fir_language"),
            }
            for p in persons
        ],
        "links": [
            {
                "source": r["person_a_id"],
                "target": r["person_b_id"],
                "relationship_type": (
                    r.get("relationship_type")
                    or "Evidence-linked Association"
                ),
                "relationship_description": r.get(
                    "relationship_description"
                ),
                "confidence": r.get("model_confidence"),
                "reason": r.get("reason"),
                "score_basis": r.get("score_basis") or [],
                "calls": r.get("phone_call_count", 0),
                "transactions": r.get("transaction_count", 0),
                "meetings": r.get("meeting_count", 0),
                "total_transaction_amount": r.get(
                    "total_transaction_amount",
                    0,
                ),
                "suspicious": r.get("suspicious", False),
                "anomaly_score": r.get("anomaly_score"),
            }
            for r in relationships
        ],
    }

    analytics = live_graph_analytics(graph_data)

    latest_runs = (
        supabase.table("analysis_runs")
        .select(
            "id, created_at, sources_processed, entities_extracted, "
            "candidate_links, suspicious_links, summary"
        )
        .eq("investigation_id", investigation_id)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )

    latest = latest_runs.data[0] if latest_runs.data else None
    saved_summary = latest.get("summary", {}) if latest else {}

    return {
        "investigation_id": investigation_id,
        "analysis_mode": "persisted_current_investigation",
        "graph": graph_data,
        **analytics,
        "analysis_run": latest,
        "entity_counts": saved_summary.get("entity_counts", {}),
        "candidate_relationships": saved_summary.get(
            "top_relationships",
            [],
        ),
        "suspicious_patterns": saved_summary.get(
            "suspicious_patterns",
            [],
        ),
        "influential_persons": saved_summary.get(
            "influential_persons",
            analytics.get("influential_persons", []),
        ),
        "community_count": saved_summary.get(
            "community_count",
            analytics.get("community_count", 0),
        ),
        "summary_text": saved_summary.get("summary_text", ""),
        "source_snapshot_hash": saved_summary.get(
            "source_snapshot_hash"
        ),
    }


# -----------------------------------------------------------------------------
# Legacy-compatible endpoints
# -----------------------------------------------------------------------------


@app.post("/api/nlp/extract")
def nlp_extract(
    body: DocumentIn,
    authorization: Optional[str] = Header(None),
):
    require_user(authorization)
    entities = extract_entities(body.content)
    content_hash = sha256_json(
        {"content": body.content, "source_type": body.source_type}
    )
    document_row = {
        "investigation_id": body.investigation_id,
        "source_type": body.source_type,
        "title": body.title,
        "content": body.content,
        "language": body.language,
        "content_hash": content_hash,
        "extracted_entities": entities,
    }
    document = supabase.table("documents").insert(document_row).execute()
    return {
        "entities": entities,
        "document": document.data[0] if document.data else None,
    }


@app.post("/api/documents")
def create_document(
    body: DocumentIn,
    authorization: Optional[str] = Header(None),
):
    return nlp_extract(body, authorization)


@app.post("/api/links")
def create_link(
    body: LinkIn,
    authorization: Optional[str] = Header(None),
):
    require_user(authorization)
    last = (
        supabase.table("network_links")
        .select("link_hash")
        .eq("investigation_id", body.investigation_id)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    previous = last.data[0]["link_hash"] if last.data else ""
    payload = body.model_dump()
    link_hash_value = hash_link(payload, previous)
    row = {
        **payload,
        "link_hash": link_hash_value,
        "previous_hash": previous,
        "created_at": utc_now(),
    }
    result = supabase.table("network_links").insert(row).execute()
    return result.data[0]


@app.get("/api/investigations/{investigation_id}/persons")
def get_persons(
    investigation_id: str,
    authorization: Optional[str] = Header(None),
):
    require_user(authorization)
    result = (
        supabase.table("persons")
        .select("*")
        .eq("investigation_id", investigation_id)
        .order("name")
        .execute()
    )
    return result.data or []


@app.get("/api/investigations/{investigation_id}/relationships")
def get_relationships(
    investigation_id: str,
    authorization: Optional[str] = Header(None),
):
    require_user(authorization)
    result = (
        supabase.table("person_relationships")
        .select("*")
        .eq("investigation_id", investigation_id)
        .execute()
    )
    return result.data or []


@app.get("/api/investigations/{investigation_id}/graph")
def graph(
    investigation_id: str,
    authorization: Optional[str] = Header(None),
):
    require_user(authorization)
    analysis = investigation_analysis(investigation_id, authorization)
    return analysis["graph"]


@app.get("/api/investigations/{investigation_id}/persons/search")
def search_persons(
    investigation_id: str,
    q: str = "",
    authorization: Optional[str] = Header(None),
):
    require_user(authorization)
    value = q.strip()
    if not value:
        return []
    results = []
    base_select = (
        "id, person_id, name, age, location, phone_num, vehicle_num, "
        "org, bank_account, crime_recorded, fir_language"
    )
    for field in ["name", "person_id", "phone_num", "vehicle_num", "org"]:
        result = (
            supabase.table("persons")
            .select(base_select)
            .eq("investigation_id", investigation_id)
            .ilike(field, f"%{value}%")
            .limit(10)
            .execute()
        )
        results.extend(result.data or [])
    unique = {person["id"]: person for person in results}
    return list(unique.values())[:10]


@app.get("/api/investigations/{investigation_id}/network/{person_id}")
def get_person_network(
    investigation_id: str,
    person_id: str,
    authorization: Optional[str] = Header(None),
):
    require_user(authorization)
    data = graph(investigation_id, authorization)
    ids = {person_id}
    for link in data["links"]:
        if link["source"] == person_id:
            ids.add(link["target"])
        elif link["target"] == person_id:
            ids.add(link["source"])
    return {
        "center": next(
            (n for n in data["nodes"] if n["id"] == person_id), {"id": person_id}
        ),
        "nodes": [n for n in data["nodes"] if n["id"] in ids],
        "links": [
            l for l in data["links"] if l["source"] in ids and l["target"] in ids
        ],
    }


@app.post("/api/tips/analyze")
def analyze_tip(
    body: TipIn,
    authorization: Optional[str] = Header(None),
):
    require_user(authorization)
    entities = extract_entities(body.text)
    return {
        "entities": entities,
        "message": "Use these extracted entities as candidate seeds. A full investigation analysis should be run against the submitted source corpus.",
    }
