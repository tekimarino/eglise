from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from .csv_store import read_csv

CONTRIB_HEADERS = ["id","timestamp","date","rubrique","montant","lieu","member_id","donateur"]
DEP_HEADERS = ["id","timestamp","date","rubrique","montant","lieu","auteur","motif"]

def _parse_float(x: Any) -> float:
    try:
        return float(str(x).replace(",", "."))
    except Exception:
        return 0.0

def _in_range(date_str: str, start: Optional[str], end: Optional[str]) -> bool:
    if not start and not end:
        return True
    try:
        d = datetime.fromisoformat(date_str[:10])
    except Exception:
        return True
    if start:
        try:
            s = datetime.fromisoformat(start[:10])
            if d < s:
                return False
        except Exception:
            pass
    if end:
        try:
            e = datetime.fromisoformat(end[:10])
            if d > e:
                return False
        except Exception:
            pass
    return True

def list_contributions(member_id: Optional[str] = None, start: Optional[str]=None, end: Optional[str]=None) -> List[Dict[str,str]]:
    rows = read_csv("transactions/contributions.csv")
    out = []
    for r in rows:
        if member_id and r.get("member_id") != member_id:
            continue
        if not _in_range(r.get("date",""), start, end):
            continue
        out.append(r)
    out.sort(key=lambda x: x.get("date",""), reverse=True)
    return out

def list_depenses(start: Optional[str]=None, end: Optional[str]=None) -> List[Dict[str,str]]:
    rows = read_csv("transactions/depenses.csv")
    out = []
    for r in rows:
        if not _in_range(r.get("date",""), start, end):
            continue
        out.append(r)
    out.sort(key=lambda x: x.get("date",""), reverse=True)
    return out

def bilan_general(member_id: Optional[str]=None, start: Optional[str]=None, end: Optional[str]=None) -> Dict[str, Any]:
    contribs = list_contributions(member_id=member_id, start=start, end=end)
    deps = [] if member_id else list_depenses(start=start, end=end)

    total_entrees = sum(_parse_float(c.get("montant")) for c in contribs)
    total_sorties = sum(_parse_float(d.get("montant")) for d in deps)
    solde = total_entrees - total_sorties

    by_rub = defaultdict(float)
    by_person = defaultdict(float)
    by_date = defaultdict(float)

    for c in contribs:
        by_rub[c.get("rubrique","")] += _parse_float(c.get("montant"))
        by_person[c.get("donateur","")] += _parse_float(c.get("montant"))
        by_date[c.get("date","")[:10]] += _parse_float(c.get("montant"))

    # depenses breakdown only for admin scope
    dep_by_rub = defaultdict(float)
    dep_by_date = defaultdict(float)
    for d in deps:
        dep_by_rub[d.get("rubrique","")] += _parse_float(d.get("montant"))
        dep_by_date[d.get("date","")[:10]] += _parse_float(d.get("montant"))

    def _top(dct, n=20):
        items = [{"key":k, "value": round(v,2)} for k,v in dct.items() if k]
        items.sort(key=lambda x: x["value"], reverse=True)
        return items[:n]

    return {
        "scope": "MEMBRE" if member_id else "GLOBAL",
        "total_entrees": round(total_entrees, 2),
        "total_sorties": round(total_sorties, 2),
        "solde": round(solde, 2),
        "bilan_entrees_par_rubrique": _top(by_rub),
        "bilan_entrees_par_personne": _top(by_person),
        "bilan_entrees_par_date": _top(by_date),
        "bilan_sorties_par_rubrique": _top(dep_by_rub) if deps else [],
        "bilan_sorties_par_date": _top(dep_by_date) if deps else [],
        "dernieres_entrees": contribs[:10],
        "dernieres_sorties": deps[:10],
    }
