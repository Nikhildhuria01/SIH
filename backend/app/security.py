import hashlib, json
from datetime import datetime, timezone

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def sha256_json(obj):
    return hashlib.sha256(canonical(obj).encode('utf-8')).hexdigest()

def hash_link(link_payload, previous_hash=''):
    body={"previous_hash": previous_hash, "payload": link_payload}
    return sha256_json(body)

def utc_now():
    return datetime.now(timezone.utc).isoformat()
