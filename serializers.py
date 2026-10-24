import base64
import json

def to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def from_base64(data_str: str) -> bytes:
    return base64.b64decode(data_str.encode('utf-8'))

def serialize_payload(payload: dict) -> str:
    return json.dumps(payload, indent=4)

def deserialize_payload(json_str: str) -> dict:
    return json.loads(json_str)