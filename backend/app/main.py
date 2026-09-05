from __future__ import annotations

import itertools
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


# Keep NLP lazy: importing the NLP module may load spaCy/model data and block startup.
def extract_entities(text: str):
    from .nlp import extract_entities as _extract_entities

    return _extract_entities(text)


def nlp_model_loaded() -> bool:
    try:
        from .nlp import NLP_MODEL_LOADED

        return NLP_MODEL_LOADED
    except Exception:
        return False


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


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Any exception raised below (e.g. a lower-level httpx/httpcore/network
    # failure while calling Supabase) would otherwise crash the ASGI
    # connection before CORSMiddleware can attach CORS headers, which shows
    # up in the browser as a misleading "blocked by CORS policy" error
    # instead of the real cause. Catching it here still goes through
    # CORSMiddleware, so the frontend gets a normal, readable error.
    print(f"Unhandled exception on {request.method} {request.url.path}:", exc)
    return JSONResponse(
        status_code=500,
        content={"detail": f"Unexpected server error: {exc}"},
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
    source_type: str
    title: Optional[str] = None
    content: str
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
    global RELATIONSHIP_MODEL
    values = relationship_features(record)
    if RELATIONSHIP_MODEL is None:
        RELATIONSHIP_MODEL = load_model(RELATIONSHIP_MODEL_PATH)
    if RELATIONSHIP_MODEL is not None:
        try:
            return float(RELATIONSHIP_MODEL.predict_proba([values])[0][1])
        except Exception as exc:
            print("Relationship model inference failed:", exc)

    # Explainable fallback if model artifact is unavailable.
    raw = (
        0.25 * min(float(record.get("calls") or 0) / 20, 1)
        + 0.22 * min(float(record.get("transactions") or 0) / 10, 1)
        + 0.18 * min(float(record.get("meetings") or 0) / 5, 1)
        + 0.15 * min(float(record.get("amount") or 0) / 250000, 1)
        + 0.20 * min(float(record.get("source_diversity") or 0) / 4, 1)
    )
    raw += 0.08 * max(
        float(record.get("shared_phone") or 0),
        float(record.get("shared_vehicle") or 0),
        float(record.get("shared_org") or 0),
        float(record.get("shared_location") or 0),
    )
    return float(max(0.0, min(1.0, raw)))


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

    for source in sources:
        entities = source["entities"]
        text = source["content"]
        profile["source_types"].add(source["source_type"].upper())

        # Only assign a unique structured field when the source contains one
        # person. This avoids attaching Rahul's phone to Amit just because both
        # appear in the same FIR.
        if len(entities.get("PERSON", [])) == 1:
            phones = entities.get("PHONE", [])
            vehicles = entities.get("VEHICLE", [])
            orgs = entities.get("ORG", [])
            locations = entities.get("GPE", [])
            banks = entities.get("BANK", [])
            if phones and not profile["phone_num"]:
                profile["phone_num"] = clean_phone(phones[0])
            if vehicles and not profile["vehicle_num"]:
                profile["vehicle_num"] = vehicles[0]
            if orgs and not profile["org"]:
                profile["org"] = orgs[0]
            if locations and not profile["location"]:
                profile["location"] = locations[0]
            if banks and not profile["bank_account"]:
                profile["bank_account"] = banks[0]

        # Lightweight age/crime extraction when explicitly written near a name.
        age_match = re.search(
            rf"\b{re.escape(name)}\b[^.\n]{{0,80}}?\bage\s*[:=]?\s*(\d{{1,3}})",
            text,
            flags=re.I,
        )
        if age_match and not profile["age"]:
            profile["age"] = int(age_match.group(1))

        if (
            source["source_type"].upper() in {"CRIMINAL_HISTORY", "FIR"}
            and not profile["crime_recorded"]
        ):
            crime_match = re.search(
                rf"\b{re.escape(name)}\b[^.\n]{{0,180}}?(?:recorded\s+categories|crime|charges?|case\s+references?)\s*[:=]?\s*([^\.\n]+)",
                text,
                flags=re.I,
            )
            if crime_match:
                profile["crime_recorded"] = crime_match.group(1).strip()

        if source["source_type"].upper() == "FIR" and not profile["fir_language"]:
            profile["fir_language"] = source.get("language", "en")

    return profile


def candidate_key(a: str, b: str) -> Tuple[str, str]:
    return tuple(sorted((a, b)))


def build_live_candidates(
    sources: List[Dict[str, Any]],
    person_profiles: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
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

    for source in sources:
        entities = source["entities"]
        people = [p for p in entities.get("PERSON", []) if normalize_text(p)]
        if len(people) < 2:
            continue

        activity = source_activity(source["source_type"], source["content"])
        source_type = source["source_type"].upper()

        phones = {clean_phone(v) for v in entities.get("PHONE", []) if clean_phone(v)}
        vehicles = {normalize_text(v) for v in entities.get("VEHICLE", []) if v}
        orgs = {normalize_text(v) for v in entities.get("ORG", []) if v}
        locations = {normalize_text(v) for v in entities.get("GPE", []) if v}

        for a_name, b_name in itertools.combinations(people, 2):
            a_key = normalize_text(a_name)
            b_key = normalize_text(b_name)
            if a_key not in person_profiles or b_key not in person_profiles:
                continue

            record = get_candidate(a_key, b_key)
            record["co_occurrences"] += 1
            record["source_types"].add(source_type)
            record["phone_call_count"] += int(activity["calls"])
            record["total_call_duration_sec"] += int(activity["duration"])
            record["transaction_count"] += int(activity["transactions"])
            record["total_transaction_amount"] += float(activity["amount"])
            record["meeting_count"] += int(activity["meetings"])

            a_profile = person_profiles[a_key]
            b_profile = person_profiles[b_key]
            if a_profile.get("phone_num") and a_profile.get(
                "phone_num"
            ) == b_profile.get("phone_num"):
                record["shared_phone"] = 1
            if a_profile.get("vehicle_num") and normalize_text(
                a_profile.get("vehicle_num")
            ) == normalize_text(b_profile.get("vehicle_num")):
                record["shared_vehicle"] = 1
            if a_profile.get("org") and normalize_text(
                a_profile.get("org")
            ) == normalize_text(b_profile.get("org")):
                record["shared_org"] = 1
            if a_profile.get("location") and normalize_text(
                a_profile.get("location")
            ) == normalize_text(b_profile.get("location")):
                record["shared_location"] = 1

        # Source may have only structured identifiers rather than names.
        # Map CDR caller/receiver phones and transaction account holders back
        # to current-investigation people; this still uses ONLY the submitted
        # source corpus, never the training dataset.
        if source_type == "CDR":
            known_people_by_phone = {
                p["phone_num"]: key
                for key, p in person_profiles.items()
                if p.get("phone_num")
            }
            phones_in_text = [
                clean_phone(x)
                for x in re.findall(r"(?:\+91[- ]?)?[6-9]\d{9}", source["content"])
            ]
            mapped = list(
                dict.fromkeys(
                    [
                        known_people_by_phone.get(p)
                        for p in phones_in_text
                        if known_people_by_phone.get(p)
                    ]
                )
            )
            if len(mapped) >= 2:
                for a_key, b_key in itertools.combinations(mapped, 2):
                    record = get_candidate(a_key, b_key)
                    record["source_types"].add("CDR")
                    record["phone_call_count"] += max(1, int(activity["calls"]))
                    record["total_call_duration_sec"] += int(activity["duration"])

        if source_type == "FINANCIAL":
            # Use explicit From Person / To Person pairs where present.
            transactions = re.split(
                r"(?=Transaction\s+\d+)", source["content"], flags=re.I
            )
            for chunk in transactions:
                from_match = re.search(r"From Person\s*:\s*([^\n]+)", chunk, flags=re.I)
                to_match = re.search(r"To Person\s*:\s*([^\n]+)", chunk, flags=re.I)
                amount_match = re.search(
                    r"Amount\s*:\s*(?:INR|Rs\.?|₹)?\s*([0-9,]+(?:\.\d+)?)",
                    chunk,
                    flags=re.I,
                )
                if from_match and to_match:
                    a_key = normalize_text(from_match.group(1))
                    b_key = normalize_text(to_match.group(1))
                    if a_key in person_profiles and b_key in person_profiles:
                        record = get_candidate(a_key, b_key)
                        record["source_types"].add("FINANCIAL")
                        record["transaction_count"] += 1
                        if amount_match:
                            record["total_transaction_amount"] += float(
                                amount_match.group(1).replace(",", "")
                            )

    results: List[Dict[str, Any]] = []
    for record in candidates.values():
        record["source_diversity"] = len(record.pop("source_types"))
        record["calls"] = record["phone_call_count"]
        record["duration"] = record["total_call_duration_sec"]
        record["transactions"] = record["transaction_count"]
        record["amount"] = record["total_transaction_amount"]
        record["meetings"] = record["meeting_count"]
        record["model_confidence"] = predict_relationship(record)
        record["reason"] = relationship_reason(record)
        record["relationship_type"] = "Potential Relationship"

        anomaly = anomaly_result(record)
        record["suspicious"] = anomaly["is_anomaly"]
        record["anomaly_score"] = anomaly["anomaly_score"]
        record["suspicious_reasons"] = anomaly["reasons"]
        results.append(record)

    results.sort(key=lambda item: item["model_confidence"], reverse=True)
    return results


def build_live_graph(
    investigation_id: str,
    person_profiles: Dict[str, Dict[str, Any]],
    candidates: List[Dict[str, Any]],
) -> Dict[str, Any]:
    # Every node ID is assigned from the current investigation only.
    key_to_id: Dict[str, str] = {}

    investigation_prefix = re.sub(
        r"[^A-Za-z0-9]",
        "",
        investigation_id,
    )[:12].upper()

    for index, key in enumerate(sorted(person_profiles), start=1):
        key_to_id[key] = f"LIVE-{investigation_prefix}-{index:04d}"

    nodes: List[Dict[str, Any]] = []
    for key, profile in person_profiles.items():
        person_id = key_to_id[key]
        nodes.append(
            {
                "id": person_id,
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
                "source_types": sorted(profile.get("source_types") or []),
            }
        )

    links: List[Dict[str, Any]] = []
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
                    f"{record['reason']} This is an analytical lead generated "
                    "from the evidence supplied for this investigation."
                ),
                "confidence": record["model_confidence"],
                "reason": record["reason"],
                "calls": record["phone_call_count"],
                "total_call_duration_sec": record["total_call_duration_sec"],
                "transactions": record["transaction_count"],
                "meetings": record["meeting_count"],
                "total_transaction_amount": record["total_transaction_amount"],
                "suspicious": record["suspicious"],
                "anomaly_score": record["anomaly_score"],
                "suspicious_reasons": record["suspicious_reasons"],
            }
        )

    return {"nodes": nodes, "links": links}


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
    if supabase is None:
        return

    # Build one source-document ID per person where possible.
    document_ids = {
        doc["source_type"]: doc["document"]["id"]
        for doc in source_documents
        if doc.get("document")
    }

    for node in graph_data["nodes"]:
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
            "crime_recorded": node.get("crime_recorded") or "Source-linked subject",
            "fir_language": node.get("fir_language"),
            "source_document_id": document_ids.get("FIR"),
        }
        payload = {k: v for k, v in payload.items() if v is not None}

        existing = (
            supabase.table("persons")
            .select("id")
            .eq("investigation_id", investigation_id)
            .eq("person_id", node["id"])
            .limit(1)
            .execute()
        )
        if existing.data:
            supabase.table("persons").update(payload).eq(
                "id", existing.data[0]["id"]
            ).execute()
        else:
            supabase.table("persons").insert(payload).execute()


def persist_relationships(
    investigation_id: str,
    graph_data: Dict[str, Any],
) -> None:
    if supabase is None:
        return

    try:
        supabase.table("person_relationships").delete().eq(
            "investigation_id", investigation_id
        ).execute()
    except Exception as exc:
        print("Relationship cleanup failed:", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Unable to reset investigation relationships: {exc}",
        )

    node_names = {node["id"]: node["name"] for node in graph_data["nodes"]}

    for index, link in enumerate(graph_data["links"], start=1):
        payload = {
            "relationship_id": (
                f"LIVE-{re.sub(r'[^A-Za-z0-9]', '', investigation_id)[:12]}-"
                f"{index:04d}"
            ),
            "investigation_id": investigation_id,
            "person_a_id": link["source"],
            "person_a_name": node_names.get(link["source"], link["source"]),
            "person_b_id": link["target"],
            "person_b_name": node_names.get(link["target"], link["target"]),
            "phone_call_count": link.get("calls", 0),
            "total_call_duration_sec": link.get("total_call_duration_sec", 0),
            "transaction_count": link.get("transactions", 0),
            "total_transaction_amount": link.get("total_transaction_amount", 0),
            "meeting_count": link.get("meetings", 0),
            "relationship_label": (
                1 if float(link.get("confidence") or 0) >= 0.5 else 0
            ),
            "ground_truth_confidence": None,
            "model_confidence": link.get("confidence"),
            "relationship_type": (
                link.get("relationship_type") or "Potential Relationship"
            ),
            "relationship_description": link.get("relationship_description"),
            "reason": link.get("reason"),
            "suspicious": bool(link.get("suspicious")),
            "anomaly_score": link.get("anomaly_score"),
        }

        try:
            supabase.table("person_relationships").insert(payload).execute()
        except Exception as first_error:
            error_text = str(first_error).lower()
            optional_schema_error = (
                "suspicious" in error_text or "anomaly_score" in error_text
            ) and ("column" in error_text or "schema cache" in error_text)

            if not optional_schema_error:
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "Unable to save a generated relationship to Supabase. "
                        f"{first_error}"
                    ),
                )

            legacy_payload = dict(payload)
            legacy_payload.pop("suspicious", None)
            legacy_payload.pop("anomaly_score", None)

            try:
                supabase.table("person_relationships").insert(legacy_payload).execute()
                print(
                    "Saved relationship without optional anomaly columns; "
                    "update Supabase schema to persist those fields."
                )
            except Exception as second_error:
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "Unable to save a generated relationship to Supabase. "
                        f"Initial error: {first_error}; Retry error: {second_error}"
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
        "nlp_model_loaded": nlp_model_loaded(),
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


@app.post("/api/investigations/{investigation_id}/analyze-sources")
def analyze_sources(
    investigation_id: str,
    body: InvestigationAnalyzeRequest,
    authorization: Optional[str] = Header(None),
):
    user_id = require_user(authorization)
    if not body.sources:
        raise HTTPException(400, "Provide at least one intelligence source")

    context_documents: List[Dict[str, Any]] = []
    persisted_documents: List[Dict[str, Any]] = []
    entity_counts: Counter[str] = Counter()
    raw_person_names: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # IMPORTANT: analysis is performed exclusively from this request's
    # submitted source corpus. Training CSVs and pre-existing unrelated
    # investigation records are not read for graph construction.
    # ------------------------------------------------------------------
    for index, source in enumerate(body.sources):
        content = source.content.strip()
        if not content:
            continue

        entities = extract_entities(content)
        for person_name in entities.get("PERSON", []):
            key = normalize_text(person_name)
            if key:
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
        persisted_documents.append(
            {
                "document": document,
                "entities": entities,
                "source_type": source.source_type.upper(),
            }
        )

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

    warnings: List[str] = []
    if not person_profiles:
        warnings.append(
            "No person names could be identified in the submitted evidence, "
            "so no relationships, network graph, or suspicious-pattern "
            "signals were generated. Try including full names in the "
            "source text."
        )
    elif len(person_profiles) == 1:
        warnings.append(
            "Only one person was identified across the submitted evidence, "
            "so no candidate relationships could be generated yet. Add "
            "evidence that mentions at least two people together."
        )
    if not nlp_model_loaded():
        warnings.append(
            "The spaCy English NLP model is not installed on the server, "
            "so entity extraction is running in a reduced-accuracy fallback "
            "mode. Run 'python -m spacy download en_core_web_sm' in the "
            "backend virtualenv and restart the API for full accuracy."
        )

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
            "relationship_type": "Potential Relationship",
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
        "warnings": warnings,
        "message": "Analysis completed from submitted investigation evidence only. Scores are analytical leads, not proof of criminality.",
    }


@app.get("/api/investigations/{investigation_id}/analysis")
def investigation_analysis(
    investigation_id: str,
    authorization: Optional[str] = Header(None),
):
    require_user(authorization)
    # Rebuild a persisted-case view when reopening an investigation. This is
    # live investigation data, not the ML training CSVs.
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
                "relationship_type": r.get("relationship_type")
                or "Potential Relationship",
                "relationship_description": r.get("relationship_description"),
                "confidence": r.get("model_confidence"),
                "reason": r.get("reason"),
                "calls": r.get("phone_call_count", 0),
                "transactions": r.get("transaction_count", 0),
                "meetings": r.get("meeting_count", 0),
                "total_transaction_amount": r.get("total_transaction_amount", 0),
                "suspicious": r.get("suspicious", False),
            }
            for r in relationships
        ],
    }
    analytics = live_graph_analytics(graph_data)
    return {
        "investigation_id": investigation_id,
        "analysis_mode": "persisted_current_investigation",
        "graph": graph_data,
        **analytics,
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
