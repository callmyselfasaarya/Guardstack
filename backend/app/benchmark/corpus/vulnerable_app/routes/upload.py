import base64
import os
import pickle
from fastapi import APIRouter, Request, HTTPException
from jinja2 import Environment

router = APIRouter()
jinja_env = Environment()

# True Positive 3: Insecure Deserialization via pickle in public endpoint
@router.post("/profile/upload-state")
async def upload_state(request: Request):
    payload = await request.body()
    try:
        decoded = base64.b64decode(payload)
        # RCE vulnerability: untrusted pickle deserialization
        obj = pickle.loads(decoded)
        return {"status": "success", "profile": str(obj)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# True Positive 4: Reflected XSS / SSTI via template string
@router.get("/profile/preview")
def preview_profile(username: str):
    template_str = f"<div>Welcome to Guardstack demo, {username}!</div>"
    template = jinja_env.from_string(template_str)
    return template.render()
