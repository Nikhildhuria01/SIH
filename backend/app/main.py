from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List
from .supabase_client import supabase
from .nlp import extract_entities
from .security import sha256_json, hash_link, utc_now

app = FastAPI(title="SIH 26189 Criminal Network Analysis API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# Models
# -------------------------


class InvestigationCreate(BaseModel):
    title: str
    description: Optional[str] = None


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
    evidence_ids: List[str] = []


class TipIn(BaseModel):
    investigation_id: str
    text: str


# -------------------------
# Authentication
# -------------------------


def require_user(authorization: Optional[str]):
    if supabase is None:
        raise HTTPException(500, "Supabase not configured")

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Access token required")

    token = authorization.split(" ", 1)[1]

    try:
        user = supabase.auth.get_user(token).user
    except Exception:
        raise HTTPException(401, "Invalid token")

    profile = (
        supabase.table("profiles").select("is_authorized").eq("id", user.id).execute()
    )

    if not profile.data or not profile.data[0]["is_authorized"]:
        raise HTTPException(403, "User not authorized")

    return user.id


# -------------------------
# Helpers
# -------------------------


def clean_phone(phone):
    if not phone:
        return None

    phone = phone.replace(" ", "").replace("-", "")

    if phone.startswith("+91"):
        phone = phone[3:]

    return phone


def get_next_person_id():
    response = (
        supabase.table("persons")
        .select("person_id")
        .order("person_id", desc=True)
        .limit(1)
        .execute()
    )

    if not response.data:
        return "P0001"

    last = response.data[0]["person_id"]

    try:
        number = int(last.replace("P", ""))
        return f"P{number+1:04d}"
    except Exception:
        return "P0001"


def save_person_from_entities(
    investigation_id, entities, fir_text, fir_language, source_document_id=None
):
    created_or_updated = []

    people = entities.get("PERSON", [])
    phones = entities.get("PHONE", [])
    vehicles = entities.get("VEHICLE", [])
    orgs = entities.get("ORG", [])
    locations = entities.get("GPE", [])
    banks = entities.get("BANK", [])

    phone = clean_phone(phones[0]) if phones else None
    vehicle = vehicles[0] if vehicles else None
    org = orgs[0] if orgs else None
    location = locations[0] if locations else None
    bank = banks[0] if banks else None

    for person_name in people:

        existing = None

        if phone:
            r = (
                supabase.table("persons")
                .select("*")
                .eq("phone_num", phone)
                .eq("investigation_id", investigation_id)
                .execute()
            )

            if r.data:
                existing = r.data[0]

        if not existing:
            r = (
                supabase.table("persons")
                .select("*")
                .eq("investigation_id", investigation_id)
                .ilike("name", person_name)
                .execute()
            )

            if r.data:
                existing = r.data[0]

        payload = {
            "name": person_name,
            "phone_num": phone,
            "vehicle_num": vehicle,
            "org": org,
            "location": location,
            "bank_account": bank,
            "crime_recorded": "Recorded in FIR",
            "fir_text": fir_text,
            "fir_language": fir_language,
            "source_document_id": source_document_id,
            "investigation_id": investigation_id,
        }

        payload = {k: v for k, v in payload.items() if v is not None}

        if existing:

            updated = (
                supabase.table("persons")
                .update(payload)
                .eq("id", existing["id"])
                .execute()
            )

            if updated.data:
                created_or_updated.append(
                    {"action": "updated", "person": updated.data[0]}
                )

        else:

            payload["person_id"] = get_next_person_id()

            inserted = supabase.table("persons").insert(payload).execute()

            if inserted.data:
                created_or_updated.append(
                    {"action": "created", "person": inserted.data[0]}
                )

    return created_or_updated


# -------------------------
# Health
# -------------------------


@app.get("/health")
def health():
    return {"status": "ok", "supabase_configured": supabase is not None}


# -------------------------
# Investigations
# -------------------------


@app.post("/api/investigations")
def create_investigation(
    body: InvestigationCreate, authorization: Optional[str] = Header(None)
):
    user_id = require_user(authorization)

    row = {
        "title": body.title,
        "description": body.description,
        "created_by": user_id,
        "status": "active",
    }

    r = supabase.table("investigations").insert(row).execute()

    return r.data[0]


# -------------------------
# NLP + FIR ingestion
# -------------------------


@app.post("/api/nlp/extract")
def nlp_extract(body: DocumentIn, authorization: Optional[str] = Header(None)):

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

    document = (supabase.table("documents").insert(document_row).execute()).data[0]

    persons = save_person_from_entities(
        investigation_id=body.investigation_id,
        entities=entities,
        fir_text=body.content,
        fir_language=body.language,
        source_document_id=document["id"],
    )

    return {
        "entities": entities,
        "document": document,
        "persons_created_or_updated": persons,
    }


# -------------------------
# Documents
# -------------------------


@app.post("/api/documents")
def create_document(body: DocumentIn, authorization: Optional[str] = Header(None)):
    require_user(authorization)

    entities = extract_entities(body.content)

    content_hash = sha256_json(
        {"content": body.content, "source_type": body.source_type}
    )

    row = {
        "investigation_id": body.investigation_id,
        "source_type": body.source_type,
        "title": body.title,
        "content": body.content,
        "language": body.language,
        "content_hash": content_hash,
        "extracted_entities": entities,
    }

    r = supabase.table("documents").insert(row).execute()

    return {"document": r.data[0], "entities": entities}


# -------------------------
# Tamper-proof links
# -------------------------


@app.post("/api/links")
def create_link(body: LinkIn, authorization: Optional[str] = Header(None)):
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

    link_hash = hash_link(payload, previous)

    row = {
        **payload,
        "link_hash": link_hash,
        "previous_hash": previous,
        "created_at": utc_now(),
    }

    r = supabase.table("network_links").insert(row).execute()

    return r.data[0]


# -------------------------
# Persons
# -------------------------


@app.get("/api/investigations/{investigation_id}/persons")
def get_persons(investigation_id: str, authorization: Optional[str] = Header(None)):
    require_user(authorization)

    r = (
        supabase.table("persons")
        .select("*")
        .eq("investigation_id", investigation_id)
        .execute()
    )

    return r.data


# -------------------------
# Relationships
# -------------------------


@app.get("/api/investigations/{investigation_id}/relationships")
def get_relationships(
    investigation_id: str, authorization: Optional[str] = Header(None)
):
    require_user(authorization)

    r = (
        supabase.table("person_relationships")
        .select("*")
        .eq("investigation_id", investigation_id)
        .execute()
    )

    return r.data

@app.get("/api/investigations/{investigation_id}/persons/search")
def search_persons(
    investigation_id: str,
    q: str = "",
    authorization: Optional[str] = Header(None)
):
    """
    Search persons within an investigation.

    Used by the frontend autocomplete/search box.
    Searches by:
    - name
    - person ID
    - phone number
    - vehicle number
    - organization
    """

    require_user(authorization)

    query = q.strip()

    if not query:
        return []

    response = (
        supabase.table("persons")
        .select(
            "id, person_id, name, age, location, phone_num, "
            "vehicle_num, org, bank_account, crime_recorded, "
            "fir_language"
        )
        .eq("investigation_id", investigation_id)
        .or_(
            f"name.ilike.%{query}%,"
            f"person_id.ilike.%{query}%,"
            f"phone_num.ilike.%{query}%,"
            f"vehicle_num.ilike.%{query}%,"
            f"org.ilike.%{query}%"
        )
        .limit(10)
        .execute()
    )

    return response.data or []


@app.get("/api/investigations/{investigation_id}/network/{person_id}")
def get_person_network(
    investigation_id: str,
    person_id: str,
    authorization: Optional[str] = Header(None)
):
    """
    Return a focused network around one selected person.

    The selected subject is the center node.
    Only the strongest/relevant 5 connections are returned.
    """

    require_user(authorization)

    # --------------------------------------------------
    # 1. Find selected person
    # --------------------------------------------------

    person_response = (
        supabase.table("persons")
        .select("*")
        .eq("investigation_id", investigation_id)
        .eq("person_id", person_id)
        .limit(1)
        .execute()
    )

    if not person_response.data:
        raise HTTPException(
            status_code=404,
            detail="Person not found."
        )

    center_person = person_response.data[0]

    # --------------------------------------------------
    # 2. Find relationships involving selected person
    # --------------------------------------------------

    relationship_response = (
        supabase.table("person_relationships")
        .select("*")
        .eq("investigation_id", investigation_id)
        .or_(
            f"person_a_id.eq.{person_id},"
            f"person_b_id.eq.{person_id}"
        )
        .execute()
    )

    relationships = relationship_response.data or []

    # --------------------------------------------------
    # 3. Calculate relevance score
    # --------------------------------------------------

    def relationship_score(r):
        model_confidence = r.get("model_confidence")

        if model_confidence is None:
            model_confidence = r.get(
                "ground_truth_confidence"
            ) or 0

        calls = r.get("phone_call_count") or 0
        transactions = r.get("transaction_count") or 0
        meetings = r.get("meeting_count") or 0

        # Frequency contributes to relevance,
        # but confidence remains the main factor.
        score = (
            float(model_confidence) * 100
            + min(calls, 50) * 0.5
            + min(transactions, 20) * 1.0
            + min(meetings, 10) * 2.0
        )

        return score

    relationships.sort(
        key=relationship_score,
        reverse=True
    )

    # Show only the strongest 5 connections.
  #  relationships = relationships[:5]

    # --------------------------------------------------
    # 4. Build nodes
    # --------------------------------------------------

    nodes = [
        {
            "id": center_person["person_id"],
            "name": center_person["name"],
            "type": "PERSON",
            "is_center": True,
            "age": center_person.get("age"),
            "location": center_person.get("location"),
            "phone_num": center_person.get("phone_num"),
            "vehicle_num": center_person.get("vehicle_num"),
            "org": center_person.get("org"),
            "bank_account": center_person.get("bank_account"),
            "crime_recorded": center_person.get(
                "crime_recorded"
            ),
            "fir_language": center_person.get(
                "fir_language"
            )
        }
    ]

    # IDs of connected people
    connected_ids = set()

    for r in relationships:

        if r["person_a_id"] == person_id:
            connected_ids.add(r["person_b_id"])

        elif r["person_b_id"] == person_id:
            connected_ids.add(r["person_a_id"])

    # --------------------------------------------------
    # 5. Fetch connected people
    # --------------------------------------------------

    connected_people = []

    for connected_id in connected_ids:

        person_result = (
            supabase.table("persons")
            .select("*")
            .eq("investigation_id", investigation_id)
            .eq("person_id", connected_id)
            .limit(1)
            .execute()
        )

        if person_result.data:
            connected_people.append(
                person_result.data[0]
            )

    # --------------------------------------------------
    # 6. Add connected nodes
    # --------------------------------------------------

    for person in connected_people:

        nodes.append(
            {
                "id": person["person_id"],
                "name": person["name"],
                "type": "PERSON",
                "is_center": False,
                "age": person.get("age"),
                "location": person.get("location"),
                "phone_num": person.get("phone_num"),
                "vehicle_num": person.get(
                    "vehicle_num"
                ),
                "org": person.get("org"),
                "bank_account": person.get(
                    "bank_account"
                ),
                "crime_recorded": person.get(
                    "crime_recorded"
                ),
                "fir_language": person.get(
                    "fir_language"
                )
            }
        )

    # --------------------------------------------------
    # 7. Build graph links
    # --------------------------------------------------

    links = []

    for r in relationships:

        model_confidence = r.get(
            "model_confidence"
        )

        if model_confidence is None:
            model_confidence = r.get(
                "ground_truth_confidence"
            )

        links.append(
            {
                "source": r["person_a_id"],
                "target": r["person_b_id"],

                "relationship_type": (
                    r.get("relationship_type")
                    or r.get("relationship_label")
                    or "Potential Relationship"
                ),

                "relationship_description": (
                    r.get("relationship_description")
                ),

                "confidence": model_confidence,

                "reason": r.get("reason"),

                "calls": r.get(
                    "phone_call_count", 0
                ),

                "transactions": r.get(
                    "transaction_count", 0
                ),

                "meetings": r.get(
                    "meeting_count", 0
                ),

                "total_transaction_amount": (
                    r.get(
                        "total_transaction_amount",
                        0
                    )
                ),

                "meeting_locations": (
                    r.get("meeting_locations")
                    or []
                ),

                "transaction_amounts": (
                    r.get("transaction_amounts")
                    or []
                ),

                "phone_call_dates": (
                    r.get("phone_call_dates")
                    or []
                )
            }
        )

    return {
        "center": {
            "id": center_person["person_id"],
            "name": center_person["name"]
        },
        "nodes": nodes,
        "links": links
    }
# -------------------------
# Graph
# -------------------------
@app.get("/api/investigations/{investigation_id}/persons/search")
def search_persons(
    investigation_id: str,
    q: str = "",
    authorization: Optional[str] = Header(None),
):
    """
    Search persons inside the selected investigation.

    Searches by:
    - name
    - person ID
    - phone
    - vehicle
    - organization
    """

    # Authenticate the investigator
    if supabase is None:
        raise HTTPException(
            status_code=500,
            detail="Supabase not configured",
        )

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Access token required",
        )

    token = authorization.split(" ", 1)[1]

    try:
        user = supabase.auth.get_user(token).user
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid access token",
        )

    # Verify authorization
    profile = (
        supabase
        .table("profiles")
        .select("is_authorized")
        .eq("id", user.id)
        .maybe_single()
        .execute()
    )

    if not profile.data or profile.data.get("is_authorized") is not True:
        raise HTTPException(
            status_code=403,
            detail="User not authorized",
        )

    query = q.strip()

    if not query:
        return []

    # ---------------------------------------------------------
    # Search name
    # ---------------------------------------------------------

    results = []

    name_result = (
        supabase
        .table("persons")
        .select(
            "id, person_id, name, age, location, "
            "phone_num, vehicle_num, org, "
            "bank_account, crime_recorded, fir_language"
        )
        .eq("investigation_id", investigation_id)
        .ilike("name", f"%{query}%")
        .limit(10)
        .execute()
    )

    results.extend(name_result.data or [])

    # ---------------------------------------------------------
    # Search person ID
    # ---------------------------------------------------------

    id_result = (
        supabase
        .table("persons")
        .select(
            "id, person_id, name, age, location, "
            "phone_num, vehicle_num, org, "
            "bank_account, crime_recorded, fir_language"
        )
        .eq("investigation_id", investigation_id)
        .ilike("person_id", f"%{query}%")
        .limit(10)
        .execute()
    )

    results.extend(id_result.data or [])

    # ---------------------------------------------------------
    # Search phone
    # ---------------------------------------------------------

    phone_result = (
        supabase
        .table("persons")
        .select(
            "id, person_id, name, age, location, "
            "phone_num, vehicle_num, org, "
            "bank_account, crime_recorded, fir_language"
        )
        .eq("investigation_id", investigation_id)
        .ilike("phone_num", f"%{query}%")
        .limit(10)
        .execute()
    )

    results.extend(phone_result.data or [])

    # ---------------------------------------------------------
    # Search vehicle
    # ---------------------------------------------------------

    vehicle_result = (
        supabase
        .table("persons")
        .select(
            "id, person_id, name, age, location, "
            "phone_num, vehicle_num, org, "
            "bank_account, crime_recorded, fir_language"
        )
        .eq("investigation_id", investigation_id)
        .ilike("vehicle_num", f"%{query}%")
        .limit(10)
        .execute()
    )

    results.extend(vehicle_result.data or [])

    # ---------------------------------------------------------
    # Search organization
    # ---------------------------------------------------------

    org_result = (
        supabase
        .table("persons")
        .select(
            "id, person_id, name, age, location, "
            "phone_num, vehicle_num, org, "
            "bank_account, crime_recorded, fir_language"
        )
        .eq("investigation_id", investigation_id)
        .ilike("org", f"%{query}%")
        .limit(10)
        .execute()
    )

    results.extend(org_result.data or [])

    # ---------------------------------------------------------
    # Remove duplicate persons
    # ---------------------------------------------------------

    unique = {}

    for person in results:
        unique[person["id"]] = person

    # Maximum 10 search results
    return list(unique.values())[:10]

@app.get("/api/investigations/{investigation_id}/graph")
def graph(investigation_id: str, authorization: Optional[str] = Header(None)):
    require_user(authorization)

    persons = (
        supabase.table("persons")
        .select("*")
        .eq("investigation_id", investigation_id)
        .execute()
        .data
    )

    relationships = (
        supabase.table("person_relationships")
        .select("*")
        .eq("investigation_id", investigation_id)
        .execute()
        .data
    )

    nodes = []

    for p in persons:
        nodes.append(
            {
                "id": p["person_id"],
                "name": p["name"],
                "type": "PERSON",
                "location": p["location"],
                "crime_recorded": p["crime_recorded"],
            }
        )

    links = []

    for r in relationships:
        links.append(
            {
                "source": r["person_a_id"],
                "target": r["person_b_id"],
                "relation": r.get("relationship_type") or "Potential Relationship",
                "relationship_type": r.get("relationship_type"),
                "relationship_description": r.get("relationship_description"),
                "confidence": (
                    r.get("model_confidence")
                    if r.get("model_confidence") is not None
                    else r.get("ground_truth_confidence")
                ),
                "reason": r.get("reason"),
                "calls": r.get("phone_call_count", 0),
                "transactions": r.get("transaction_count", 0),
                "meetings": r.get("meeting_count", 0),
                "total_transaction_amount": r.get("total_transaction_amount", 0),
            }
        )

    return {"nodes": nodes, "links": links}


# -------------------------
# Quick tip analyzer
# -------------------------


@app.post("/api/tips/analyze")
def analyze_tip(body: TipIn, authorization: Optional[str] = Header(None)):
    require_user(authorization)

    entities = extract_entities(body.text)

    return {
        "entities": entities,
        "message": "Use extracted entities as seeds for graph expansion.",
    }
