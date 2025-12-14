
from __future__ import annotations

import csv
import json
import os
import uuid
import hashlib
import datetime
import hmac

import requests
from pathlib import Path
from typing import Optional, List, Dict, Any

import jwt
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, StrictInt

# ---------------------------
# Paths & constants
# ---------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
CFG_DIR = DATA_DIR / "config"
TX_DIR = DATA_DIR / "transactions"
INV_DIR = DATA_DIR / "inventory"
EXPORT_DIR = DATA_DIR / "exports"

USERS_JSON = CFG_DIR / "users.json"
APP_CONFIG_JSON = CFG_DIR / "app_config.json"
MEMBERS_CSV = CFG_DIR / "members.csv"
CONTRIB_CSV = TX_DIR / "contributions.csv"
DEPENSES_CSV = TX_DIR / "depenses.csv"
PAYMENTS_CSV = TX_DIR / "payments.csv"

ITEMS_CSV = INV_DIR / "items.csv"
MOVES_CSV = INV_DIR / "moves.csv"

JWT_SECRET = os.environ.get("APP_SECRET", "CHANGE_ME_DEV_SECRET")
JWT_ALGO = "HS256"
TOKEN_TTL_HOURS = 24

CINETPAY_APIKEY = os.environ.get("CINETPAY_APIKEY", "").strip()
CINETPAY_SITE_ID = os.environ.get("CINETPAY_SITE_ID", "").strip()
CINETPAY_SECRET_KEY = os.environ.get("CINETPAY_SECRET_KEY", "").strip()
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").strip()
CINETPAY_CHANNELS = "MOBILE_MONEY"
CINETPAY_CURRENCY = "XOF"
CINETPAY_ENABLED = bool(CINETPAY_APIKEY and CINETPAY_SITE_ID)

ROLE_ADMIN = "ADMIN"
ROLE_MEMBER = "MEMBRE"

MEMBERS_HEADERS = ["member_id","nom","prenoms","email","residence","telephone","fonction","active","created_at"]
PAYMENTS_HEADERS = ["payment_id","transaction_id","kind","member_id","amount","currency","status","contrib_id","payment_url","payload_json","cinetpay_raw","created_at","updated_at"]


def norm_username(u: str) -> str:
    """Normalize usernames for reliable lookup (trim + lower)."""
    return (u or "").strip().lower()

def norm_password(p: str) -> str:
    """Trim passwords to avoid invisible space issues from copy/paste."""
    return (p or "").strip()


def utc_now() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def ensure_csv(path: Path, headers: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        with path.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(headers)

def ensure_csv_headers(path: Path, headers: List[str]) -> None:
    """
    Ensure CSV exists and matches the given header order.
    If file exists with different headers, migrate by adding missing columns and reordering.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        with path.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(headers)
        return

    # Read existing
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        try:
            existing_headers = next(reader)
        except StopIteration:
            existing_headers = []
    # If already good, done
    if existing_headers == headers:
        return

    # Load rows as dicts using existing headers (DictReader tolerates missing/new)
    with path.open("r", newline="", encoding="utf-8") as f:
        dict_reader = csv.DictReader(f)
        rows = list(dict_reader)

    # Rewrite with requested headers
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in rows:
            clean = {h: ("" if r.get(h) is None else str(r.get(h))) for h in headers}
            w.writerow(clean)


# Ensure files exist
ensure_csv_headers(MEMBERS_CSV, MEMBERS_HEADERS)
ensure_csv(CONTRIB_CSV, ["id","member_id","nom","prenoms","rubrique","lieu","montant","date","note","created_at","created_by"])
ensure_csv_headers(PAYMENTS_CSV, PAYMENTS_HEADERS)
ensure_csv(DEPENSES_CSV, ["id","beneficiaire","motif","lieu","montant","date","created_at","created_by","justificatif_path"])
ensure_csv(ITEMS_CSV, ["id","nom","categorie","stock","created_at"])
ensure_csv(MOVES_CSV, ["id","item_id","item_nom","type","quantite","motif","date","created_at","created_by"])

EXPORT_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------
# JSON helpers
# ---------------------------
def read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def read_config() -> Dict[str, Any]:
    if not APP_CONFIG_JSON.exists():
        write_json(APP_CONFIG_JSON, {"rubriques": ["Dîme","Offrandes","Cotisations","Autre"], "lieux":["Temple principal","Annexe","En ligne"], "currency":"XOF"})
    return read_json(APP_CONFIG_JSON)

# ---------------------------
# CSV helpers
# ---------------------------
def read_csv_dicts(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def append_csv_row(path: Path, row: Dict[str, Any], headers: List[str]) -> None:
    ensure_csv(path, headers)
    with path.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        # cast to str
        clean = {k: ("" if row.get(k) is None else str(row.get(k))) for k in headers}
        w.writerow(clean)

def write_csv_all(path: Path, headers: List[str], rows: List[Dict[str, Any]]) -> None:
    ensure_csv(path, headers)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in rows:
            clean = {k: ("" if r.get(k) is None else str(r.get(k))) for k in headers}
            w.writerow(clean)


# ---------------------------
# CinetPay helpers
# ---------------------------
def get_public_base_url(request: Request) -> str:
    """Return the public base url (scheme://host) for building absolute callback URLs."""
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL.rstrip("/")
    # try proxy headers (Render / reverse proxies)
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{proto}://{host}".rstrip("/")

def cinetpay_init(transaction_id: str, amount: int, description: str, notify_url: str, return_url: str, customer: Dict[str, str]) -> Dict[str, Any]:
    """Call CinetPay init API and return parsed JSON."""
    if not CINETPAY_ENABLED:
        raise HTTPException(status_code=500, detail="CinetPay non configuré (CINETPAY_APIKEY/CINETPAY_SITE_ID).")
    payload = {
        "apikey": CINETPAY_APIKEY,
        "site_id": CINETPAY_SITE_ID,
        "transaction_id": transaction_id,
        "amount": amount,
        "currency": CINETPAY_CURRENCY,
        "description": description,
        "notify_url": notify_url,
        "return_url": return_url,
        "channels": CINETPAY_CHANNELS,
        "lang": "fr",
    }
    # optional customer fields
    for k in ["customer_name","customer_surname","customer_email","customer_phone_number","customer_address","customer_city","customer_country"]:
        v = (customer.get(k) or "").strip()
        if v:
            payload[k] = v
    try:
        r = requests.post("https://api-checkout.cinetpay.com/v2/payment", json=payload, timeout=30)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erreur de connexion à CinetPay: {e}")
    try:
        out = r.json()
    except Exception:
        raise HTTPException(status_code=502, detail=f"Réponse CinetPay invalide (HTTP {r.status_code}).")
    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Erreur CinetPay (HTTP {r.status_code}): {out}")
    return out

def cinetpay_check(transaction_id: str) -> Dict[str, Any]:
    if not CINETPAY_ENABLED:
        raise HTTPException(status_code=500, detail="CinetPay non configuré.")
    payload = {"apikey": CINETPAY_APIKEY, "site_id": CINETPAY_SITE_ID, "transaction_id": transaction_id}
    try:
        r = requests.post("https://api-checkout.cinetpay.com/v2/payment/check", json=payload, timeout=30)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erreur de connexion à CinetPay: {e}")
    try:
        out = r.json()
    except Exception:
        raise HTTPException(status_code=502, detail=f"Réponse CinetPay invalide (HTTP {r.status_code}).")
    return out

def load_payments() -> List[Dict[str, Any]]:
    return read_csv_dicts(PAYMENTS_CSV)

def save_payments(rows: List[Dict[str, Any]]) -> None:
    write_csv_all(PAYMENTS_CSV, PAYMENTS_HEADERS, rows)

def upsert_payment(row: Dict[str, Any]) -> None:
    rows = load_payments()
    found = False
    for i, r in enumerate(rows):
        if r.get("transaction_id") == row.get("transaction_id"):
            rows[i] = {**r, **row}
            found = True
            break
    if not found:
        rows.append(row)
    save_payments(rows)

def find_payment(transaction_id: str) -> Optional[Dict[str, Any]]:
    for r in load_payments():
        if r.get("transaction_id") == transaction_id:
            return r
    return None

def create_contribution_from_payment(payment: Dict[str, Any], created_by: str) -> str:
    """Idempotently create contribution once payment is ACCEPTED."""
    if payment.get("contrib_id"):
        return payment["contrib_id"]
    member_id = payment.get("member_id") or ""
    if not member_id:
        raise HTTPException(status_code=400, detail="Paiement sans member_id.")
    payload = {}
    try:
        payload = json.loads(payment.get("payload_json") or "{}")
    except Exception:
        payload = {}
    mr = get_member_row(member_id) or {}
    nom = mr.get("nom","")
    prenoms = mr.get("prenoms","")
    cid = "c_" + uuid.uuid4().hex[:10]
    append_csv_row(
        CONTRIB_CSV,
        {
            "id": cid,
            "member_id": member_id,
            "nom": nom,
            "prenoms": prenoms,
            "rubrique": payload.get("rubrique",""),
            "lieu": payload.get("lieu",""),
            "montant": int(payload.get("montant") or 0),
            "date": payload.get("date",""),
            "note": payload.get("note",""),
            "created_at": utc_now(),
            "created_by": created_by,
        },
        ["id","member_id","nom","prenoms","rubrique","lieu","montant","date","note","created_at","created_by"]
    )
    # update payment with contrib_id
    upsert_payment({
        "transaction_id": payment.get("transaction_id",""),
        "contrib_id": cid,
        "updated_at": utc_now(),
    })
    return cid

def sync_payment_status(transaction_id: str, actor_username: str) -> Dict[str, Any]:
    payment = find_payment(transaction_id)
    if not payment:
        raise HTTPException(status_code=404, detail="Transaction introuvable.")
    out = cinetpay_check(transaction_id)
    # expected: out["data"]["status"] == "ACCEPTED"
    status = ""
    try:
        status = (out.get("data") or {}).get("status","")
    except Exception:
        status = ""
    new_status = status or payment.get("status","")
    upd = {
        "transaction_id": transaction_id,
        "status": new_status,
        "cinetpay_raw": json.dumps(out, ensure_ascii=False),
        "updated_at": utc_now(),
    }
    upsert_payment({**payment, **upd})
    payment = find_payment(transaction_id) or {**payment, **upd}
    contrib_id = payment.get("contrib_id")
    if (new_status == "ACCEPTED") and not contrib_id:
        contrib_id = create_contribution_from_payment(payment, actor_username)
        payment = find_payment(transaction_id) or payment
    return {
        "transaction_id": transaction_id,
        "status": payment.get("status",""),
        "contrib_id": payment.get("contrib_id",""),
    }

# ---------------------------
# Auth / password
# ---------------------------
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def make_salt() -> str:
    return uuid.uuid4().hex[:16]

def hash_password(password: str, salt: str) -> str:
    return sha256_hex(salt + password)

def load_users() -> Dict[str, Any]:
    data = read_json(USERS_JSON)
    if "users" not in data or not isinstance(data.get("users"), list):
        data["users"] = []

    # Migrate + normalize existing users (username trim/lower, active default)
    changed = False
    for u in data["users"]:
        if "username" in u:
            un = norm_username(u.get("username", ""))
            if u.get("username") != un:
                u["username"] = un
                changed = True
        else:
            u["username"] = ""
            changed = True
        if "active" not in u:
            u["active"] = True
            changed = True

    # Ensure default admin exists (dev convenience)
    if not any(u.get("role") == ROLE_ADMIN for u in data["users"]):
        salt = make_salt()
        data["users"].append({
            "id": "u_admin",
            "username": "admin",
            "display_name": "Administrateur principal",
            "role": ROLE_ADMIN,
            "active": True,
            "member_id": None,
            "salt": salt,
            "password_hash": hash_password("Admin123!", salt),
            "created_at": utc_now()
        })
        changed = True

    if changed:
        write_json(USERS_JSON, data)
    return data

def save_users(data: Dict[str, Any]) -> None:
    write_json(USERS_JSON, data)

def find_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    uname = norm_username(username)
    if not uname:
        return None
    data = load_users()
    for u in data["users"]:
        if norm_username(u.get("username","")) == uname:
            return u
    return None

def find_user_by_id(uid: str) -> Optional[Dict[str, Any]]:
    data = load_users()
    for u in data["users"]:
        if u.get("id") == uid:
            return u
    return None

def make_token(user: Dict[str, Any]) -> str:
    payload = {
        "sub": user["id"],
        "username": user["username"],
        "role": user["role"],
        "member_id": user.get("member_id"),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_TTL_HOURS),
        "iat": datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def decode_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expirée. Reconnectez-vous.")
    except Exception:
        raise HTTPException(status_code=401, detail="Token invalide.")

def get_current_user(authorization: Optional[str] = None) -> Dict[str, Any]:
    # FastAPI doesn't auto inject header without explicit dependency; we use Depends wrapper below
    raise HTTPException(status_code=401, detail="Not implemented")

from fastapi import Header
def current_user_dep(Authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    if not Authorization or not Authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Non authentifié.")
    token = Authorization.split(" ",1)[1].strip()
    claims = decode_token(token)
    user = find_user_by_id(claims.get("sub",""))
    if not user or not user.get("active", False):
        raise HTTPException(status_code=401, detail="Compte inactif ou introuvable.")
    # ensure role/member_id from token are consistent
    return {
        "id": user["id"],
        "username": user["username"],
        "display_name": user.get("display_name") or user["username"],
        "role": user["role"],
        "active": user.get("active", True),
        "member_id": user.get("member_id"),
    }

def require_admin(user: Dict[str, Any]) -> None:
    if user.get("role") != ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="Accès réservé à l'administrateur.")

# ---------------------------
# Pydantic models (declare BEFORE routes)
# ---------------------------
class LoginIn(BaseModel):
    username: str
    password: str

class RegisterIn(BaseModel):
    nom: str
    prenoms: str
    email: str = ""
    residence: str = ""
    telephone: str = ""
    fonction: str = ""
    username: str
    password: str

class MemberIn(BaseModel):
    nom: str
    prenoms: str
    email: str = ""
    residence: str = ""
    telephone: str = ""
    fonction: str = ""
    active: bool = True

class UserCreateIn(BaseModel):
    # admin creates a member + account in one shot
    nom: str
    prenoms: str
    email: str = ""
    residence: str = ""
    telephone: str = ""
    fonction: str = ""
    username: str
    password: str
    active: bool = True

class ContributionIn(BaseModel):
    member_id: Optional[str] = None  # admin may set; member ignored
    rubrique: str
    lieu: str
    montant: StrictInt = Field(ge=500)
    date: str  # YYYY-MM-DD
    note: str = ""


class ContributionUpdateIn(BaseModel):
    # admin-only update; fields optional
    member_id: Optional[str] = None
    rubrique: Optional[str] = None
    lieu: Optional[str] = None
    montant: Optional[StrictInt] = Field(default=None, ge=500)
    date: Optional[str] = None  # YYYY-MM-DD
    note: Optional[str] = None
class DepenseIn(BaseModel):
    beneficiaire: str
    motif: str
    lieu: str
    montant: StrictInt = Field(ge=500)
    date: str

class DepenseUpdateIn(BaseModel):
    # admin-only update; fields optional
    beneficiaire: Optional[str] = None
    motif: Optional[str] = None
    lieu: Optional[str] = None
    montant: Optional[StrictInt] = Field(default=None, ge=500)
    date: Optional[str] = None  # YYYY-MM-DD

class ItemIn(BaseModel):
    nom: str
    categorie: str = ""
    stock: int = 0

class MoveIn(BaseModel):
    item_id: str
    type: str  # IN/OUT
    quantite: int = Field(ge=1)
    motif: str = ""
    date: str  # YYYY-MM-DD

# ---------------------------
# App & static
# ---------------------------
app = FastAPI(title="Gestion Contributions Église", version="4.1")

# Serve frontend
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "frontend")), name="static")

@app.get("/", response_class=HTMLResponse)
def index():
    index_path = BASE_DIR / "frontend" / "index.html"
    return index_path.read_text(encoding="utf-8")

# ---------------------------
# Auth endpoints
# ---------------------------
@app.post("/api/auth/login")
def login(payload: LoginIn):
    user = find_user_by_username(norm_username(payload.username))
    if not user:
        raise HTTPException(status_code=401, detail="Identifiants invalides.")
    if not user.get("active", False):
        raise HTTPException(status_code=403, detail="Compte désactivé.")
    salt = user.get("salt","")
    password = norm_password(payload.password)
    if hash_password(password, salt) != user.get("password_hash",""):
        raise HTTPException(status_code=401, detail="Identifiants invalides.")
    return {"access_token": make_token(user), "token_type":"bearer"}

@app.post("/api/auth/register")
def register(payload: RegisterIn):
    # Public registration: creates member profile + member account (active immediately)
    username = norm_username(payload.username)
    password = norm_password(payload.password)
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username et mot de passe requis.")
    if find_user_by_username(username):
        raise HTTPException(status_code=409, detail="Ce nom d'utilisateur est déjà utilisé.")

    member_id = "m_" + uuid.uuid4().hex[:10]
    append_csv_row(
        MEMBERS_CSV,
        {
            "member_id": member_id,
            "nom": payload.nom.strip(),
            "prenoms": payload.prenoms.strip(),
            "email": payload.email.strip(),
            "residence": payload.residence.strip(),
            "telephone": payload.telephone.strip(),
            "fonction": payload.fonction.strip(),
            "active": "1",
            "created_at": utc_now(),
        },
        MEMBERS_HEADERS
    )

    salt = make_salt()
    user_id = "u_" + uuid.uuid4().hex[:10]
    users = load_users()
    users["users"].append({
        "id": user_id,
        "username": username,
        "display_name": f"{payload.prenoms.strip()} {payload.nom.strip()}".strip(),
        "role": ROLE_MEMBER,
        "active": True,
        "member_id": member_id,
        "salt": salt,
        "password_hash": hash_password(password, salt),
        "created_at": utc_now()
    })
    save_users(users)

    # Auto login after register
    token = make_token(find_user_by_id(user_id))
    return {"access_token": token, "token_type":"bearer"}

# ---------------------------
# Config endpoint
# ---------------------------
@app.get("/api/config")
def get_config(user=Depends(current_user_dep)):
    cfg = read_config()
    cfg["current_user"] = {
        "id": user["id"],
        "username": user["username"],
        "display_name": user["display_name"],
        "role": user["role"],
        "member_id": user.get("member_id"),
    }
    return cfg

class ConfigUpdateIn(BaseModel):
    rubriques: Optional[List[str]] = None
    lieux: Optional[List[str]] = None
    currency: Optional[str] = None

@app.put("/api/admin/config")
def admin_update_config(payload: ConfigUpdateIn, user=Depends(current_user_dep)):
    require_admin(user)
    cfg = read_config()

    if payload.rubriques is not None:
        rub = [str(r).strip() for r in (payload.rubriques or []) if str(r).strip()]
        seen=set(); rub2=[]
        for r in rub:
            key=r.lower()
            if key in seen:
                continue
            seen.add(key); rub2.append(r)
        if not rub2:
            raise HTTPException(status_code=400, detail="Au moins une rubrique est requise.")
        cfg["rubriques"] = rub2

    if payload.lieux is not None:
        lieux = [str(l).strip() for l in (payload.lieux or []) if str(l).strip()]
        seen=set(); lieux2=[]
        for l in lieux:
            key=l.lower()
            if key in seen:
                continue
            seen.add(key); lieux2.append(l)
        if not lieux2:
            raise HTTPException(status_code=400, detail="Au moins un lieu est requis.")
        cfg["lieux"] = lieux2

    if payload.currency is not None and str(payload.currency).strip():
        cfg["currency"] = str(payload.currency).strip()

    write_json(APP_CONFIG_JSON, cfg)
    return {"ok": True, "config": cfg}

# ---------------------------
# Members & users (admin)
# ---------------------------
@app.get("/api/members")
def list_members(user=Depends(current_user_dep)):
    require_admin(user)
    rows = read_csv_dicts(MEMBERS_CSV)
    # normalize active
    for r in rows:
        r["active"] = (r.get("active","1") not in ("0","false","False",""))
    return rows


@app.get("/api/members/{member_id}")
def get_member(member_id: str, user=Depends(current_user_dep)):
    require_admin(user)
    rows = read_csv_dicts(MEMBERS_CSV)
    for r in rows:
        if r.get("member_id") == member_id:
            r["active"] = (r.get("active","1") not in ("0","false","False",""))
            return r
    raise HTTPException(status_code=404, detail="Membre introuvable.")

@app.put("/api/members/{member_id}")
def update_member(member_id: str, payload: MemberIn, user=Depends(current_user_dep)):
    require_admin(user)
    rows = read_csv_dicts(MEMBERS_CSV)
    found = None
    for r in rows:
        if r.get("member_id") == member_id:
            found = r
            break
    if not found:
        raise HTTPException(status_code=404, detail="Membre introuvable.")

    found["nom"] = payload.nom.strip()
    found["prenoms"] = payload.prenoms.strip()
    found["email"] = payload.email.strip()
    found["residence"] = payload.residence.strip()
    found["telephone"] = payload.telephone.strip()
    found["fonction"] = payload.fonction.strip()
    found["active"] = "1" if payload.active else "0"

    write_csv_all(MEMBERS_CSV, MEMBERS_HEADERS, rows)

    # Keep display_name consistent for linked user
    data = load_users()
    changed = False
    for u in data["users"]:
        if u.get("member_id") == member_id:
            u["display_name"] = f"{payload.prenoms.strip()} {payload.nom.strip()}".strip()
            changed = True
    if changed:
        save_users(data)

    return {"ok": True}

@app.delete("/api/members/{member_id}")
def delete_member(member_id: str, user=Depends(current_user_dep)):
    """Delete member profile and deactivate account(s). Contributions remain for audit."""
    require_admin(user)
    rows = read_csv_dicts(MEMBERS_CSV)
    before = len(rows)
    rows = [r for r in rows if r.get("member_id") != member_id]
    if len(rows) == before:
        raise HTTPException(status_code=404, detail="Membre introuvable.")
    write_csv_all(MEMBERS_CSV, MEMBERS_HEADERS, rows)

    data = load_users()
    changed = False
    for u in data["users"]:
        if u.get("member_id") == member_id:
            u["active"] = False
            changed = True
    if changed:
        save_users(data)

    return {"ok": True}

# ---------------------------
# Mon compte (membre)
# ---------------------------
class ProfileUpdateIn(BaseModel):
    nom: Optional[str] = None
    prenoms: Optional[str] = None
    email: Optional[str] = None
    residence: Optional[str] = None
    telephone: Optional[str] = None
    fonction: Optional[str] = None
    password: Optional[str] = None

def get_member_row(member_id: str) -> Optional[Dict[str, str]]:
    rows = read_csv_dicts(MEMBERS_CSV)
    for r in rows:
        if r.get("member_id") == member_id:
            return r
    return None

@app.get("/api/me")
def get_me(user=Depends(current_user_dep)):
    if user.get("role") != ROLE_MEMBER:
        raise HTTPException(status_code=403, detail="Réservé aux membres.")
    mid = user.get("member_id") or ""
    m = get_member_row(mid)
    if not m:
        raise HTTPException(status_code=404, detail="Profil membre introuvable.")
    return {
        "member_id": mid,
        "username": user.get("username",""),
        "display_name": user.get("display_name",""),
        "nom": m.get("nom",""),
        "prenoms": m.get("prenoms",""),
        "email": m.get("email",""),
        "residence": m.get("residence",""),
        "telephone": m.get("telephone",""),
        "fonction": m.get("fonction",""),
        "active": (m.get("active","1") not in ("0","false","False","")),
        "created_at": m.get("created_at",""),
    }

@app.put("/api/me")
def update_me(payload: ProfileUpdateIn, user=Depends(current_user_dep)):
    if user.get("role") != ROLE_MEMBER:
        raise HTTPException(status_code=403, detail="Réservé aux membres.")
    mid = user.get("member_id") or ""
    if not mid:
        raise HTTPException(status_code=400, detail="Compte membre invalide.")

    # Validate email if provided
    if payload.email is not None:
        em = payload.email.strip()
        if em and ("@" not in em or "." not in em):
            raise HTTPException(status_code=400, detail="Email invalide.")
    else:
        em = None

    rows = read_csv_dicts(MEMBERS_CSV)
    found = None
    for r in rows:
        if r.get("member_id") == mid:
            found = r
            break
    if not found:
        raise HTTPException(status_code=404, detail="Profil membre introuvable.")

    if payload.nom is not None:
        found["nom"] = payload.nom.strip()
    if payload.prenoms is not None:
        found["prenoms"] = payload.prenoms.strip()
    if em is not None:
        found["email"] = em
    if payload.residence is not None:
        found["residence"] = payload.residence.strip()
    if payload.telephone is not None:
        found["telephone"] = payload.telephone.strip()
    if payload.fonction is not None:
        found["fonction"] = payload.fonction.strip()

    write_csv_all(MEMBERS_CSV, MEMBERS_HEADERS, rows)

    # Update user display_name and optionally password
    users = load_users()
    uid = user.get("id")
    new_display = f"{found.get('prenoms','').strip()} {found.get('nom','').strip()}".strip()
    changed = False
    for u in users["users"]:
        if u.get("id") == uid:
            u["display_name"] = new_display
            changed = True
            if payload.password:
                pw = norm_password(payload.password)
                if not pw:
                    raise HTTPException(status_code=400, detail="Mot de passe invalide.")
                salt = make_salt()
                u["salt"] = salt
                u["password_hash"] = hash_password(pw, salt)
            break
    if changed:
        save_users(users)

    return {"ok": True, "display_name": new_display}


@app.post("/api/admin/create_member_account")
def admin_create_member_account(payload: UserCreateIn, user=Depends(current_user_dep)):
    require_admin(user)

    username = norm_username(payload.username)

    password = norm_password(payload.password)
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username et mot de passe requis.")

    if find_user_by_username(username):
        raise HTTPException(status_code=409, detail="Nom d'utilisateur déjà utilisé.")

    member_id = "m_" + uuid.uuid4().hex[:10]
    append_csv_row(
        MEMBERS_CSV,
        {
            "member_id": member_id,
            "nom": payload.nom.strip(),
            "prenoms": payload.prenoms.strip(),
            "email": payload.email.strip(),
            "residence": payload.residence.strip(),
            "telephone": payload.telephone.strip(),
            "fonction": payload.fonction.strip(),
            "active": "1" if payload.active else "0",
            "created_at": utc_now(),
        },
        MEMBERS_HEADERS
    )

    salt = make_salt()
    user_id = "u_" + uuid.uuid4().hex[:10]
    users = load_users()
    users["users"].append({
        "id": user_id,
        "username": username,
        "display_name": f"{payload.prenoms.strip()} {payload.nom.strip()}".strip(),
        "role": ROLE_MEMBER,
        "active": bool(payload.active),
        "member_id": member_id,
        "salt": salt,
        "password_hash": hash_password(password, salt),
        "created_at": utc_now()
    })
    save_users(users)
    return {"ok": True, "member_id": member_id, "user_id": user_id}

@app.get("/api/users")
def list_users(user=Depends(current_user_dep)):
    require_admin(user)
    data = load_users()
    # hide hashes
    out = []
    for u in data["users"]:
        out.append({
            "id": u["id"],
            "username": u["username"],
            "display_name": u.get("display_name",""),
            "role": u.get("role",""),
            "active": u.get("active",True),
            "member_id": u.get("member_id"),
            "created_at": u.get("created_at",""),
        })
    return out

@app.put("/api/users/{user_id}")
def update_user(user_id: str, patch: Dict[str, Any], user=Depends(current_user_dep)):
    require_admin(user)
    data = load_users()
    found = None
    for u in data["users"]:
        if u.get("id") == user_id:
            found = u
            break
    if not found:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")

    # allowed fields
    for k in ["display_name","active","role","member_id","username"]:
        if k in patch:
            if k == "username":
                # ensure unique
                existing = find_user_by_username(norm_username(str(patch[k])))
                if existing and existing.get("id") != user_id:
                    raise HTTPException(status_code=409, detail="Nom d'utilisateur déjà utilisé.")
            found[k] = norm_username(str(patch[k])) if k == "username" else patch[k]

    if "password" in patch and patch["password"]:
        salt = found.get("salt") or make_salt()
        found["salt"] = salt
        found["password_hash"] = hash_password(norm_password(str(patch["password"])), salt)

    save_users(data)
    return {"ok": True}



@app.patch("/api/users/{user_id}")
def patch_user(user_id: str, patch: Dict[str, Any], user=Depends(current_user_dep)):
    """Partial update for user accounts (used by UI for activate/deactivate and password reset)."""
    return update_user(user_id, patch, user)

@app.delete("/api/users/{user_id}")
def delete_user(user_id: str, user=Depends(current_user_dep)):
    require_admin(user)
    data = load_users()
    before = len(data["users"])
    data["users"] = [u for u in data["users"] if u.get("id") != user_id]
    if len(data["users"]) == before:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
    save_users(data)
    return {"ok": True}

# ---------------------------
# Paiements (CinetPay)
# ---------------------------

@app.post("/api/payments/cinetpay/init-contribution")
def init_contribution_payment(payload: ContributionIn, request: Request, user=Depends(current_user_dep)):
    # Members only: admin can still create contributions without payment
    if user["role"] != ROLE_MEMBER:
        raise HTTPException(status_code=403, detail="Réservé aux membres.")
    cfg = read_config()
    if payload.rubrique not in cfg.get("rubriques", []):
        raise HTTPException(status_code=400, detail="Rubrique invalide.")
    if payload.lieu not in cfg.get("lieux", []):
        raise HTTPException(status_code=400, detail="Lieu invalide.")

    member_id = user.get("member_id")
    if not member_id:
        raise HTTPException(status_code=400, detail="Compte membre mal configuré (member_id manquant).")

    base = get_public_base_url(request)
    notify_url = f"{base}/api/payments/cinetpay/notify"
    return_url = f"{base}/?cinetpay_return=1"

    transaction_id = "CONTR_" + uuid.uuid4().hex[:16]
    # customer info
    m = None
    for r in read_csv_dicts(MEMBERS_CSV):
        if r.get("member_id") == member_id:
            m = r
            break
    customer = {
        "customer_name": (m.get("nom") if m else ""),
        "customer_surname": (m.get("prenoms") if m else ""),
        "customer_email": (m.get("email") if m else ""),
        "customer_phone_number": (m.get("telephone") if m else ""),
        "customer_country": "CI",
        "customer_city": (m.get("residence") if m else ""),
        "customer_address": (m.get("residence") if m else ""),
    }
    description = f"Contribution {payload.rubrique}"

    raw = cinetpay_init(
        transaction_id=transaction_id,
        amount=int(payload.montant),
        description=description,
        notify_url=notify_url,
        return_url=return_url,
        customer=customer,
    )
    data = raw.get("data") or {}
    payment_url = data.get("payment_url") or data.get("payment_url") or data.get("payment_url")
    if not payment_url:
        # some APIs return payment_url inside data["payment_url"]
        payment_url = data.get("payment_url") or data.get("payment_url")
    if not payment_url:
        raise HTTPException(status_code=502, detail=f"CinetPay n'a pas retourné payment_url: {raw}")

    payment_row = {
        "payment_id": "p_" + uuid.uuid4().hex[:10],
        "transaction_id": transaction_id,
        "kind": "contribution",
        "member_id": member_id,
        "amount": int(payload.montant),
        "currency": CINETPAY_CURRENCY,
        "status": "PENDING",
        "contrib_id": "",
        "payment_url": payment_url,
        "payload_json": json.dumps({
            "rubrique": payload.rubrique,
            "lieu": payload.lieu,
            "montant": int(payload.montant),
            "date": payload.date,
            "note": payload.note,
        }, ensure_ascii=False),
        "cinetpay_raw": json.dumps(raw, ensure_ascii=False),
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    upsert_payment(payment_row)
    return {"transaction_id": transaction_id, "payment_url": payment_url}


@app.api_route("/api/payments/cinetpay/notify", methods=["GET","POST"])
async def cinetpay_notify(request: Request):
    # CinetPay pings GET to test availability. Always return 200.
    if request.method == "GET":
        return {"ok": True}

    # accept form or json
    form = {}
    try:
        form = dict(await request.form())
    except Exception:
        try:
            form = await request.json()
        except Exception:
            form = {}

    transaction_id = form.get("transaction_id") or form.get("cpm_trans_id") or form.get("cpm_trans_id ")
    if not transaction_id:
        return {"ok": True}
    # Trigger a check (do not trust payload alone)
    try:
        sync_payment_status(transaction_id, actor_username="system")
    except Exception:
        # swallow errors: webhook retries
        pass
    return {"ok": True}


@app.post("/api/payments/cinetpay/sync/{transaction_id}")
def cinetpay_sync(transaction_id: str, user=Depends(current_user_dep)):
    payment = find_payment(transaction_id)
    if not payment:
        raise HTTPException(status_code=404, detail="Transaction introuvable.")
    # member can only sync their own payment
    if user["role"] == ROLE_MEMBER and (payment.get("member_id") != user.get("member_id")):
        raise HTTPException(status_code=403, detail="Accès refusé.")
    return sync_payment_status(transaction_id, actor_username=user.get("username","system"))


@app.get("/api/payments/{transaction_id}")
def get_payment(transaction_id: str, user=Depends(current_user_dep)):
    payment = find_payment(transaction_id)
    if not payment:
        raise HTTPException(status_code=404, detail="Transaction introuvable.")
    if user["role"] == ROLE_MEMBER and (payment.get("member_id") != user.get("member_id")):
        raise HTTPException(status_code=403, detail="Accès refusé.")
    return {
        "transaction_id": payment.get("transaction_id"),
        "status": payment.get("status"),
        "contrib_id": payment.get("contrib_id"),
    }


@app.api_route("/cinetpay/return", methods=["GET","POST"])
@app.api_route("/cinetpay/return/", methods=["GET","POST"], include_in_schema=False)
async def cinetpay_return(request: Request):
    # CinetPay returns transaction_id via GET or POST x-www-form-urlencoded
    tx = request.query_params.get("transaction_id") or request.query_params.get("cpm_trans_id")
    if not tx and request.method == "POST":
        try:
            form = dict(await request.form())
            tx = form.get("transaction_id") or form.get("cpm_trans_id")
        except Exception:
            tx = None
    # Redirect back to home so frontend can sync and refresh
    if not tx:
        return RedirectResponse(url="/", status_code=302)
    return RedirectResponse(url=f"/?cinetpay_return=1&transaction_id={tx}", status_code=302)


# ---------------------------
# Contributions
# ---------------------------
def get_member_label(member_id: str) -> Dict[str, str]:
    rows = read_csv_dicts(MEMBERS_CSV)
    for r in rows:
        if r.get("member_id") == member_id:
            return {"nom": r.get("nom",""), "prenoms": r.get("prenoms","")}
    return {"nom": "", "prenoms": ""}

@app.get("/api/contributions")
def list_contributions(user=Depends(current_user_dep)):
    rows = read_csv_dicts(CONTRIB_CSV)
    if user["role"] == ROLE_MEMBER:
        rows = [r for r in rows if r.get("member_id") == (user.get("member_id") or "")]
    # convert amounts
    for r in rows:
        try:
            r["montant"] = int(float(r.get("montant","0") or 0))
        except:
            r["montant"] = 0.0
    return rows

@app.post("/api/contributions")
def create_contribution(payload: ContributionIn, user=Depends(current_user_dep)):
    cfg = read_config()
    if payload.rubrique not in cfg.get("rubriques", []):
        raise HTTPException(status_code=400, detail="Rubrique invalide.")
    if payload.lieu not in cfg.get("lieux", []):
        raise HTTPException(status_code=400, detail="Lieu invalide.")

    if user["role"] == ROLE_MEMBER:
        member_id = user.get("member_id")
        if not member_id:
            raise HTTPException(status_code=400, detail="Compte membre mal configuré (member_id manquant).")
        if CINETPAY_ENABLED:
            raise HTTPException(status_code=400, detail="Paiement requis: utilisez le bouton de paiement pour enregistrer une contribution.")
    else:
        member_id = payload.member_id
        if not member_id:
            raise HTTPException(status_code=400, detail="member_id requis pour l'admin (choisir un membre).")

    names = get_member_label(member_id)
    cid = "c_" + uuid.uuid4().hex[:10]
    append_csv_row(
        CONTRIB_CSV,
        {
            "id": cid,
            "member_id": member_id,
            "nom": nom,
            "prenoms": prenoms,
            "rubrique": payload.rubrique,
            "lieu": payload.lieu,
            "montant": payload.montant,
            "date": payload.date,
            "note": payload.note,
            "created_at": utc_now(),
            "created_by": user["username"],
        },
        ["id","member_id","nom","prenoms","rubrique","lieu","montant","date","note","created_at","created_by"]
    )
    return {"ok": True, "id": cid}

# ---------------------------
# Depenses (admin only)
# ---------------------------

@app.put("/api/contributions/{contrib_id}")
def update_contribution(contrib_id: str, payload: ContributionUpdateIn, user=Depends(current_user_dep)):
    require_admin(user)
    cfg = read_config()

    # validate optional fields
    if payload.rubrique is not None and payload.rubrique not in cfg.get("rubriques", []):
        raise HTTPException(status_code=400, detail="Rubrique invalide.")
    if payload.lieu is not None and payload.lieu not in cfg.get("lieux", []):
        raise HTTPException(status_code=400, detail="Lieu invalide.")

    rows = read_csv_dicts(CONTRIB_CSV)
    found = None
    for r in rows:
        if r.get("id") == contrib_id:
            found = r
            break
    if not found:
        raise HTTPException(status_code=404, detail="Contribution introuvable.")

    # Apply updates
    if payload.member_id is not None and payload.member_id != found.get("member_id"):
        names = get_member_label(payload.member_id)
        found["member_id"] = payload.member_id
        found["nom"] = names.get("nom","")
        found["prenoms"] = names.get("prenoms","")

    if payload.rubrique is not None:
        found["rubrique"] = payload.rubrique
    if payload.lieu is not None:
        found["lieu"] = payload.lieu
    if payload.montant is not None:
        found["montant"] = str(int(payload.montant))
    if payload.date is not None:
        found["date"] = payload.date
    if payload.note is not None:
        found["note"] = payload.note

    write_csv_all(
        CONTRIB_CSV,
        ["id","member_id","nom","prenoms","rubrique","lieu","montant","date","note","created_at","created_by"],
        rows
    )
    return {"ok": True}
@app.get("/api/depenses")
def list_depenses(user=Depends(current_user_dep)):
    require_admin(user)
    rows = read_csv_dicts(DEPENSES_CSV)
    for r in rows:
        try:
            r["montant"] = int(float(r.get("montant","0") or 0))
        except:
            r["montant"] = 0.0
    return rows

@app.post("/api/depenses")
def create_depense(payload: DepenseIn, user=Depends(current_user_dep)):
    require_admin(user)
    did = "d_" + uuid.uuid4().hex[:10]
    append_csv_row(
        DEPENSES_CSV,
        {
            "id": did,
            "beneficiaire": payload.beneficiaire,
            "motif": payload.motif,
            "lieu": payload.lieu,
            "montant": payload.montant,
            "date": payload.date,
            "created_at": utc_now(),
            "created_by": user["username"],
            "justificatif_path": "",
        },
        ["id","beneficiaire","motif","lieu","montant","date","created_at","created_by","justificatif_path"]
    )
    return {"ok": True, "id": did}

@app.put("/api/depenses/{depense_id}")
def update_depense(depense_id: str, payload: DepenseUpdateIn, user=Depends(current_user_dep)):
    require_admin(user)
    rows = read_csv_dicts(DEPENSES_CSV)
    found = None
    for r in rows:
        if r.get("id") == depense_id:
            found = r
            break
    if not found:
        raise HTTPException(status_code=404, detail="Dépense introuvable.")

    # optional updates
    if payload.beneficiaire is not None:
        found["beneficiaire"] = payload.beneficiaire
    if payload.motif is not None:
        found["motif"] = payload.motif
    if payload.lieu is not None:
        found["lieu"] = payload.lieu
    if payload.montant is not None:
        found["montant"] = payload.montant
    if payload.date is not None:
        found["date"] = payload.date

    write_csv_all(
        DEPENSES_CSV,
        ["id","beneficiaire","motif","lieu","montant","date","created_at","created_by","justificatif_path"],
        rows
    )
    return {"ok": True}


@app.post("/api/depenses/{depense_id}/justificatif")
def upload_justificatif(depense_id: str, file: UploadFile = File(...), user=Depends(current_user_dep)):
    require_admin(user)
    rows = read_csv_dicts(DEPENSES_CSV)
    found = None
    for r in rows:
        if r.get("id") == depense_id:
            found = r
            break
    if not found:
        raise HTTPException(status_code=404, detail="Dépense introuvable.")
    ext = Path(file.filename).suffix.lower() if file.filename else ".bin"
    fname = f"justif_{depense_id}{ext}"
    out_path = DATA_DIR / "uploads"
    out_path.mkdir(parents=True, exist_ok=True)
    full = out_path / fname
    with full.open("wb") as f:
        f.write(file.file.read())
    found["justificatif_path"] = str(full.relative_to(DATA_DIR))
    # rewrite
    write_csv_all(
        DEPENSES_CSV,
        ["id","beneficiaire","motif","lieu","montant","date","created_at","created_by","justificatif_path"],
        rows
    )
    return {"ok": True, "path": found["justificatif_path"]}

# ---------------------------
# Inventory (admin)
# ---------------------------
@app.get("/api/inventory/items")
def inv_items(user=Depends(current_user_dep)):
    require_admin(user)
    rows = read_csv_dicts(ITEMS_CSV)
    for r in rows:
        try:
            r["stock"] = int(float(r.get("stock","0") or 0))
        except:
            r["stock"] = 0
    return rows

@app.post("/api/inventory/items")
def inv_add_item(payload: ItemIn, user=Depends(current_user_dep)):
    require_admin(user)
    iid = "i_" + uuid.uuid4().hex[:10]
    append_csv_row(
        ITEMS_CSV,
        {"id": iid, "nom": payload.nom, "categorie": payload.categorie, "stock": payload.stock, "created_at": utc_now()},
        ["id","nom","categorie","stock","created_at"]
    )
    return {"ok": True, "id": iid}

@app.get("/api/inventory/moves")
def inv_moves(user=Depends(current_user_dep)):
    require_admin(user)
    rows = read_csv_dicts(MOVES_CSV)
    return rows

@app.post("/api/inventory/moves")
def inv_add_move(payload: MoveIn, user=Depends(current_user_dep)):
    require_admin(user)
    items = read_csv_dicts(ITEMS_CSV)
    item = None
    for it in items:
        if it.get("id") == payload.item_id:
            item = it
            break
    if not item:
        raise HTTPException(status_code=404, detail="Article introuvable.")
    stock = int(float(item.get("stock","0") or 0))
    if payload.type not in ("IN","OUT"):
        raise HTTPException(status_code=400, detail="Type doit être IN ou OUT.")
    if payload.type == "OUT" and stock < payload.quantite:
        raise HTTPException(status_code=400, detail="Stock insuffisant.")
    stock = stock + payload.quantite if payload.type == "IN" else stock - payload.quantite
    item["stock"] = str(stock)
    write_csv_all(ITEMS_CSV, ["id","nom","categorie","stock","created_at"], items)

    mid = "m_" + uuid.uuid4().hex[:10]
    append_csv_row(
        MOVES_CSV,
        {
            "id": mid,
            "item_id": payload.item_id,
            "item_nom": item.get("nom",""),
            "type": payload.type,
            "quantite": payload.quantite,
            "motif": payload.motif,
            "date": payload.date,
            "created_at": utc_now(),
            "created_by": user["username"],
        },
        ["id","item_id","item_nom","type","quantite","motif","date","created_at","created_by"]
    )
    return {"ok": True, "id": mid}

# ---------------------------
# Reports
# ---------------------------
def sum_float(rows, key):
    s = 0.0
    for r in rows:
        try:
            s += float(r.get(key,0) or 0)
        except:
            pass
    return s

@app.get("/api/reports/bilan-general")
def bilan_general(user=Depends(current_user_dep)):
    contrib = read_csv_dicts(CONTRIB_CSV)
    dep = read_csv_dicts(DEPENSES_CSV)

    if user["role"] == ROLE_MEMBER:
        mid = user.get("member_id") or ""
        contrib = [c for c in contrib if c.get("member_id") == mid]
        dep = []  # members don't see global expenses

    total_entrees = sum_float(contrib, "montant")
    total_sorties = sum_float(dep, "montant")
    solde = total_entrees - total_sorties

    # latest
    def latest(rows, n=5):
        rows2 = sorted(rows, key=lambda r: r.get("date",""), reverse=True)
        out=[]
        for r in rows2[:n]:
            out.append({
                "date": r.get("date",""),
                "personne": f"{r.get('prenoms','')} {r.get('nom','')}".strip() if "nom" in r else "",
                "rubrique": r.get("rubrique","") or r.get("motif",""),
                "montant": float(r.get("montant","0") or 0),
                "beneficiaire": r.get("beneficiaire",""),
                "motif": r.get("motif",""),
            })
        return out

    return {
        "total_entrees": total_entrees,
        "total_sorties": total_sorties,
        "solde": solde,
        "last_entrees": latest(contrib, 5),
        "last_depenses": latest(dep, 5),
    }

# ---------------------------
# Exports
# ---------------------------
@app.post("/api/exports/pdf")
def export_pdf(user=Depends(current_user_dep)):
    # PDF (portrait): totals + latest tables (scoped)
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    rep = bilan_general(user)
    file_id = "pdf_" + uuid.uuid4().hex[:10]
    out = EXPORT_DIR / f"{file_id}.pdf"

    c = canvas.Canvas(str(out), pagesize=A4)
    w, h = A4

    title = "Rapport - Bilan général" if user["role"] == ROLE_ADMIN else "Rapport - Mes sorties"

    c.setFont("Helvetica-Bold", 18)
    c.drawString(30, h-40, title)
    c.setFont("Helvetica", 11)
    c.drawString(30, h-65, f"Généré le: {utc_now()}   |   Utilisateur: {user['username']} ({user['role']})")

    c.setFont("Helvetica-Bold", 14)
    if user["role"] == ROLE_ADMIN:
        c.drawString(30, h-100, f"Total entrées: {rep['total_entrees']:.2f}")
        c.drawString(30, h-125, f"Total sorties: {rep['total_sorties']:.2f}")
        c.drawString(30, h-150, f"Solde: {rep['solde']:.2f}")
        y = h-190
    else:
        # For members, show only their total contributions as "sorties" and hide solde.
        c.drawString(30, h-100, f"Total sorties: {rep['total_entrees']:.2f}")
        y = h-160

    # Helpers
    def new_page():
        nonlocal y
        c.showPage()
        c.setFont("Helvetica-Bold", 18)
        c.drawString(30, h-40, title)
        c.setFont("Helvetica", 11)
        c.drawString(30, h-65, f"Généré le: {utc_now()}   |   Utilisateur: {user['username']} ({user['role']})")
        y = h-90

    # Table last contributions (member-scoped when role==MEMBER)
    c.setFont("Helvetica-Bold", 13)
    c.drawString(30, y, "Dernières entrées" if user["role"] == ROLE_ADMIN else "Mes dernières sorties")
    y -= 18
    c.setFont("Helvetica-Bold", 10)
    headers = ["Date", "Personne", "Rubrique", "Montant"]
    # Portrait A4 is narrower: choose tighter columns and right-align amount.
    xs = [30, 110, 260, w-30]
    for i, head in enumerate(headers):
        if head == "Montant":
            c.drawRightString(xs[i], y, head)
        else:
            c.drawString(xs[i], y, head)
    y -= 14
    c.setFont("Helvetica", 10)
    for r in rep["last_entrees"]:
        c.drawString(xs[0], y, str(r.get("date",""))[:10])
        c.drawString(xs[1], y, (r.get("personne","") or "")[:18])
        c.drawString(xs[2], y, (r.get("rubrique","") or "")[:28])
        c.drawRightString(xs[3], y, f"{float(r.get('montant',0) or 0):.2f}")
        y -= 14
        if y < 70:
            new_page()

            # repeat table header on new pages
            c.setFont("Helvetica-Bold", 13)
            c.drawString(30, y, "Dernières entrées" if user["role"] == ROLE_ADMIN else "Mes dernières sorties")
            y -= 18
            c.setFont("Helvetica-Bold", 10)
            for i, head in enumerate(headers):
                if head == "Montant":
                    c.drawRightString(xs[i], y, head)
                else:
                    c.drawString(xs[i], y, head)
            y -= 14
            c.setFont("Helvetica", 10)

    # Admin can include expenses
    if user["role"] == ROLE_ADMIN:
        y -= 10
        c.setFont("Helvetica-Bold", 13)
        c.drawString(30, y, "Dernières dépenses")
        y -= 18
        c.setFont("Helvetica-Bold", 10)
        headers = ["Date", "Bénéficiaire", "Motif", "Montant"]
        xs = [30, 140, 300, w-30]
        for i, head in enumerate(headers):
            if head == "Montant":
                c.drawRightString(xs[i], y, head)
            else:
                c.drawString(xs[i], y, head)
        y -= 14
        c.setFont("Helvetica", 10)
        for r in rep["last_depenses"]:
            c.drawString(xs[0], y, str(r.get("date",""))[:10])
            c.drawString(xs[1], y, (r.get("beneficiaire","") or "")[:22])
            c.drawString(xs[2], y, (r.get("motif","") or "")[:26])
            c.drawRightString(xs[3], y, f"{float(r.get('montant',0) or 0):.2f}")
            y -= 14
            if y < 70:
                new_page()

                # repeat expenses header on new pages
                c.setFont("Helvetica-Bold", 13)
                c.drawString(30, y, "Dernières dépenses")
                y -= 18
                c.setFont("Helvetica-Bold", 10)
                for i, head in enumerate(headers):
                    if head == "Montant":
                        c.drawRightString(xs[i], y, head)
                    else:
                        c.drawString(xs[i], y, head)
                y -= 14
                c.setFont("Helvetica", 10)

    c.save()
    return {"file_id": file_id}

@app.post("/api/exports/xlsx")
def export_xlsx(user=Depends(current_user_dep)):
    from openpyxl import Workbook

    contrib = read_csv_dicts(CONTRIB_CSV)
    dep = read_csv_dicts(DEPENSES_CSV)
    if user["role"] == ROLE_MEMBER:
        mid = user.get("member_id") or ""
        contrib = [c for c in contrib if c.get("member_id") == mid]
        dep = []

    file_id = "xlsx_" + uuid.uuid4().hex[:10]
    out = EXPORT_DIR / f"{file_id}.xlsx"

    wb = Workbook()
    ws = wb.active
    ws.title = "Entrées"

    # Force print layout to PORTRAIT for all exports.
    try:
        ws.page_setup.orientation = "portrait"
        ws.page_setup.paperSize = 9  # A4
        ws.sheet_properties.pageSetUpPr.fitToPage = True
        ws.page_setup.fitToWidth = 1
        ws.page_setup.fitToHeight = 0
    except Exception:
        # Safe fallback: orientation is just a print hint.
        pass

    ws.append(["id","date","member_id","nom","prenoms","rubrique","lieu","montant","note","created_at","created_by"])
    for r in contrib:
        ws.append([r.get("id",""), r.get("date",""), r.get("member_id",""), r.get("nom",""), r.get("prenoms",""),
                   r.get("rubrique",""), r.get("lieu",""), float(r.get("montant","0") or 0), r.get("note",""),
                   r.get("created_at",""), r.get("created_by","")])

    if user["role"] == ROLE_ADMIN:
        ws2 = wb.create_sheet("Dépenses")

        # Force print layout to PORTRAIT for expenses sheet as well.
        try:
            ws2.page_setup.orientation = "portrait"
            ws2.page_setup.paperSize = 9  # A4
            ws2.sheet_properties.pageSetUpPr.fitToPage = True
            ws2.page_setup.fitToWidth = 1
            ws2.page_setup.fitToHeight = 0
        except Exception:
            pass

        ws2.append(["id","date","beneficiaire","motif","lieu","montant","created_at","created_by","justificatif_path"])
        for r in dep:
            ws2.append([r.get("id",""), r.get("date",""), r.get("beneficiaire",""), r.get("motif",""), r.get("lieu",""),
                        float(r.get("montant","0") or 0), r.get("created_at",""), r.get("created_by",""), r.get("justificatif_path","")])

    wb.save(out)
    return {"file_id": file_id}

@app.get("/api/files")
def download_file(file_id: str, user=Depends(current_user_dep)):
    # allow download of exports
    # only in exports dir
    # try pdf then xlsx
    for ext in (".pdf",".xlsx"):
        p = EXPORT_DIR / f"{file_id}{ext}"
        if p.exists():
            return FileResponse(str(p), filename=p.name)
    raise HTTPException(status_code=404, detail="Fichier introuvable.")