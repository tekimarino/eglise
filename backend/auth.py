from __future__ import annotations

import hashlib
import os
import time
from typing import Any, Dict, Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .csv_store import read_json

JWT_SECRET = os.environ.get("JWT_SECRET", "CHANGE_ME_IN_RENDER")
JWT_ALG = "HS256"
TOKEN_TTL_SECONDS = int(os.environ.get("TOKEN_TTL_SECONDS", "28800"))  # 8h

security = HTTPBearer(auto_error=False)

def _users_store() -> Dict[str, Any]:
    return read_json("config/users.json", default={"version": 1, "items": []})

def _roles_store() -> Dict[str, Any]:
    return read_json("config/roles.json", default={"version": 1, "items": []})

def _find_user(username: str) -> Optional[Dict[str, Any]]:
    data = _users_store()
    return next((u for u in data.get("items", []) if u.get("username") == username), None)

def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()

def verify_password(username: str, password: str) -> Dict[str, Any]:
    u = _find_user(username)
    if not u or not u.get("active", True):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    salt = u.get("salt", "")
    if hash_password(password, salt) != u.get("password_hash"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return u

def create_token(user: Dict[str, Any]) -> str:
    payload = {
        "sub": user["username"],
        "role": user.get("role", "MEMBRE"),
        "name": user.get("display_name", user["username"]),
        "member_id": user.get("member_id"),
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def get_current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Dict[str, Any]:
    if not creds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = creds.credentials
    payload = decode_token(token)
    username = payload.get("sub")
    u = _find_user(username)
    if not u or not u.get("active", True):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user")
    # attach token claims (member_id might change if admin edited)
    u = dict(u)
    u["token_member_id"] = payload.get("member_id")
    return u

def is_admin(user: Dict[str, Any]) -> bool:
    return user.get("role") == "ADMIN"

def has_permission(user: Dict[str, Any], perm: str) -> bool:
    if user.get("role") == "ADMIN":
        return True
    roles = _roles_store().get("items", [])
    r = next((x for x in roles if x.get("code") == user.get("role")), None)
    if not r:
        return False
    perms = r.get("permissions", [])
    return "*" in perms or perm in perms

def require_permission(perm: str):
    def _dep(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        if not has_permission(user, perm):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return user
    return _dep

def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if not is_admin(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")
    return user
