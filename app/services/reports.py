"""PDF exposure reports."""

import io
from collections import Counter
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from ..db import Doc

INK = colors.HexColor("#08111f")
CYAN = colors.HexColor("#0891b2")
MUTED = colors.HexColor("#5b6b85")
SEV = {"critical": colors.HexColor("#d6284b"), "high": colors.HexColor("#e46a1c"),
       "medium": colors.HexColor("#c79a12"), "low": colors.HexColor("#2a8fb5")}


def _styles():
    ss = getSampleStyleSheet()
    return {
        "eyebrow": ParagraphStyle("eyebrow", parent=ss["Normal"], fontName="Courier-Bold", fontSize=8, textColor=CYAN, spaceAfter=4),
        "h1": ParagraphStyle("h1", parent=ss["Title"], fontName="Helvetica-Bold", fontSize=22, textColor=INK, alignment=TA_LEFT, spaceAfter=4),
        "h2": ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=13, textColor=INK, spaceBefore=12, spaceAfter=6),
        "body": ParagraphStyle("body", parent=ss["Normal"], fontName="Helvetica", fontSize=9.5, textColor=INK, leading=13),
        "muted": ParagraphStyle("muted", parent=ss["Normal"], fontName="Helvetica", fontSize=8.5, textColor=MUTED, leading=11),
        "cell": ParagraphStyle("cell", parent=ss["Normal"], fontName="Helvetica", fontSize=8, textColor=INK, leading=10),
        "mono": ParagraphStyle("mono", parent=ss["Normal"], fontName="Courier", fontSize=7.5, textColor=INK, leading=9.5),
    }


def _esc(s: str | None) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_pdf(user: Doc, findings: list[Doc], scans: list[Doc], title: str, subtitle: str) -> bytes:
    st = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=title, author="GhostTrace")

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Courier", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(16 * mm, 9 * mm, "GHOSTTRACE / EXPOSURE INTELLIGENCE  ·  CONFIDENTIAL")
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {d.page}")
        canvas.restoreState()

    open_f = [f for f in findings if f.status == "open"]
    sev = Counter(f.severity for f in open_f)
    story = [
        Paragraph("GHOSTTRACE EXPOSURE REPORT", st["eyebrow"]),
        Paragraph(_esc(title), st["h1"]),
        Paragraph(_esc(subtitle), st["muted"]),
        Paragraph(f"Prepared for {_esc(user.full_name or user.email)}{' · ' + _esc(user.organization) if user.organization else ''} · "
                  f"{datetime.now(timezone.utc).strftime('%d %b %Y %H:%M UTC')}", st["muted"]),
        Spacer(1, 10),
    ]

    kpis = [["Open findings", "Critical", "High", "Medium", "Low", "Scans"],
            [str(len(open_f)), str(sev["critical"]), str(sev["high"]), str(sev["medium"]), str(sev["low"]), str(len(scans))]]
    t = Table(kpis, colWidths=[(A4[0] - 32 * mm) / 6] * 6)
    t.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, 0), "Helvetica", 7.5), ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
        ("FONT", (0, 1), (-1, 1), "Helvetica-Bold", 18), ("TEXTCOLOR", (0, 1), (-1, 1), INK),
        ("TEXTCOLOR", (1, 1), (1, 1), SEV["critical"]), ("TEXTCOLOR", (2, 1), (2, 1), SEV["high"]),
        ("TEXTCOLOR", (3, 1), (3, 1), SEV["medium"]), ("TEXTCOLOR", (4, 1), (4, 1), SEV["low"]),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#d5dde9")), ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f4f7fb")),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story += [t, Spacer(1, 6)]

    story.append(Paragraph("Summary", st["h2"]))
    if open_f:
        top_cat = Counter(f.credential_type for f in open_f).most_common(3)
        story.append(Paragraph(
            f"GhostTrace found <b>{len(open_f)}</b> open credential exposure(s). The most common types are "
            + ", ".join(f"{_esc(n)} ({c})" for n, c in top_cat)
            + ". Critical and high findings should be revoked and rotated immediately; removing a secret from the latest "
              "commit does not remove it from git history.", st["body"]))
    else:
        story.append(Paragraph("No open credential exposures were found.", st["body"]))

    story.append(Paragraph("Findings", st["h2"]))
    rows = [["Sev.", "Risk", "Type", "Location", "Secret (masked)"]]
    for f in sorted(open_f, key=lambda x: -x.risk_score)[:200]:
        loc = f"{f.repository + '/' if f.repository else ''}{f.file_path or ''}{':' + str(f.line_number) if f.line_number else ''}"
        if f.in_history_only:
            loc += f" (history {f.commit_sha[:7] if f.commit_sha else ''})"
        rows.append([
            Paragraph(f"<font size='7' color='{SEV[f.severity].hexval().replace('0x', '#')}'><b>{f.severity.upper()}</b></font>", st["cell"]),
            Paragraph(f"{f.risk_score:.0f}", st["cell"]),
            Paragraph(_esc(f.credential_type), st["cell"]),
            Paragraph(_esc(loc), st["mono"]),
            Paragraph(_esc(f.secret_masked), st["mono"]),
        ])
    widths = [20 * mm, 11 * mm, 36 * mm, 63 * mm, 48 * mm]
    ft = Table(rows, colWidths=widths, repeatRows=1)
    ft.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), INK), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f7fb")]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#dfe6f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(ft if len(rows) > 1 else Paragraph("None.", st["body"]))

    story.append(Paragraph("Recommended actions", st["h2"]))
    for line in [
        "Revoke and rotate every critical and high finding at the provider (AWS IAM, GitHub, Stripe, etc.).",
        "Purge secrets from git history with git filter-repo or BFG, then force-push and invalidate forks where possible.",
        "Move secrets into a secrets manager or CI/CD environment variables and add .env files to .gitignore.",
        "Enable pre-commit secret scanning and keep GhostTrace monitors active on your organization.",
    ]:
        story.append(Paragraph(f"• {line}", st["body"]))

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
