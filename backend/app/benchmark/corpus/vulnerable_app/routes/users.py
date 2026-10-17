import sqlite3
import hashlib
from fastapi import APIRouter, Request

router = APIRouter()

# True Positive 1: Direct SQL Injection in public route (Reachable + Public Input)
@router.get("/user/search")
def search_user(request: Request, user_id: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Flawed query construction via f-string
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    return {"results": rows}

# True Positive 2: Weak MD5 Password Hashing
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()

# Candidate Unreachable Dead Code: Vulnerable pattern in helper function never called by any route
def _legacy_dead_internal_query_helper(raw_id: str):
    conn = sqlite3.connect("legacy.db")
    cursor = conn.cursor()
    # Unreachable from any API entrypoint
    cursor.execute(f"DELETE FROM logs WHERE id = {raw_id}")
    conn.commit()