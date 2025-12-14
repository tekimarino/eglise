from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas

from openpyxl import Workbook

def export_pdf_table(out_path: Path, title: str, columns: List[str], rows: List[Dict[str, Any]]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pagesize = landscape(A4)
    c = canvas.Canvas(str(out_path), pagesize=pagesize)
    w, h = pagesize

    c.setFont("Helvetica-Bold", 14)
    c.drawString(2*cm, h-1.5*cm, title)

    c.setFont("Helvetica", 9)
    c.drawString(2*cm, h-2.2*cm, f"Généré le {datetime.now().isoformat(sep=' ', timespec='seconds')}")

    # Table layout
    left = 1.5*cm
    top = h - 3*cm
    row_h = 0.7*cm
    col_w = (w - 3*cm) / max(1, len(columns))

    # Header background (simple)
    c.setLineWidth(0.5)
    for j, col in enumerate(columns):
        x = left + j*col_w
        c.setFont("Helvetica-Bold", 9)
        c.drawString(x+2, top, str(col)[:30])

    y = top - row_h
    c.setFont("Helvetica", 8)

    for i, r in enumerate(rows):
        if y < 1.5*cm:
            c.showPage()
            c.setFont("Helvetica-Bold", 14)
            c.drawString(2*cm, h-1.5*cm, title)
            y = h - 3*cm
            c.setFont("Helvetica", 8)

        for j, col in enumerate(columns):
            x = left + j*col_w
            val = r.get(col, "")
            s = str(val)
            if len(s) > 40:
                s = s[:37] + "..."
            c.drawString(x+2, y, s)
        y -= row_h

    c.save()

def export_xlsx(out_path: Path, sheet_name: str, columns: List[str], rows: List[Dict[str, Any]]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    wb = Workbook()
    ws = wb.active
    ws.title = sheet_name[:31]
    ws.append(columns)
    for r in rows:
        ws.append([r.get(c, "") for c in columns])
    wb.save(str(out_path))
