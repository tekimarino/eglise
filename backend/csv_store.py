from __future__ import annotations

import csv
import json
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

# Project root = ../ (backend folder is inside project root)
ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"

_lock = threading.Lock()

@contextmanager
def file_lock():
    """In-process lock (enough for local dev)."""
    _lock.acquire()
    try:
        yield
    finally:
        _lock.release()

def new_uuid() -> str:
    return uuid.uuid4().hex

def _path(rel: str) -> Path:
    return DATA_DIR / rel

def ensure_dir(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)

def read_json(rel: str, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    p = _path(rel)
    if not p.exists():
        return default if default is not None else {"version": 1, "items": []}
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)

def write_json(rel: str, obj: Dict[str, Any]) -> None:
    p = _path(rel)
    ensure_dir(p)
    with p.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def ensure_csv(rel: str, headers: List[str]) -> Path:
    p = _path(rel)
    ensure_dir(p)
    if not p.exists():
        with p.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=headers)
            w.writeheader()
    return p

def read_csv(rel: str) -> List[Dict[str, str]]:
    p = _path(rel)
    if not p.exists():
        return []
    with p.open("r", newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        return list(r)

def write_csv(rel: str, rows: List[Dict[str, Any]], headers: List[str]) -> None:
    p = _path(rel)
    ensure_dir(p)
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for row in rows:
            w.writerow({h: row.get(h, "") for h in headers})

def append_csv_row(rel: str, row: Dict[str, Any], headers: List[str]) -> None:
    p = ensure_csv(rel, headers)
    with p.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writerow({h: row.get(h, "") for h in headers})

def update_csv_row(rel: str, key_field: str, key_value: str, patch: Dict[str, Any], headers: List[str]) -> None:
    rows = read_csv(rel)
    found = False
    for r in rows:
        if r.get(key_field) == key_value:
            for k, v in patch.items():
                if k in headers:
                    r[k] = "" if v is None else str(v)
            found = True
            break
    if not found:
        raise KeyError(f"{key_field}={key_value} not found")
    write_csv(rel, rows, headers)

def delete_csv_row(rel: str, key_field: str, key_value: str, headers: List[str]) -> None:
    rows = read_csv(rel)
    new_rows = [r for r in rows if r.get(key_field) != key_value]
    if len(new_rows) == len(rows):
        raise KeyError(f"{key_field}={key_value} not found")
    write_csv(rel, new_rows, headers)
