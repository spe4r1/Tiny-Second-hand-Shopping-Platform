from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "secure_coding_report.md"
OUT_DIR = ROOT / "output" / "pdf"
OUTPUT = OUT_DIR / "[WHS][secure-coding][XX반]이름(0000).pdf"


def register_font():
    candidates = [
        Path(r"C:\Windows\Fonts\malgun.ttf"),
        Path(r"C:\Windows\Fonts\malgunsl.ttf"),
        Path("/usr/share/fonts/truetype/nanum/NanumGothic.ttf"),
    ]
    for path in candidates:
        if path.exists():
            pdfmetrics.registerFont(TTFont("Korean", str(path)))
            return "Korean"
    return "Helvetica"


def inline(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("`", "")
    )


def parse_markdown(lines):
    blocks = []
    i = 0
    while i < len(lines):
        line = lines[i].rstrip("\n")
        if not line.strip():
            i += 1
            continue
        if line.startswith("```"):
            code = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                code.append(lines[i].rstrip("\n"))
                i += 1
            blocks.append(("code", "<br/>".join(inline(x) for x in code)))
            i += 1
            continue
        if line.startswith("|"):
            table = []
            while i < len(lines) and lines[i].startswith("|"):
                cells = [inline(c.strip()) for c in lines[i].strip().strip("|").split("|")]
                if not all(set(c) <= {"-", " "} for c in cells):
                    table.append(cells)
                i += 1
            blocks.append(("table", table))
            continue
        if line.startswith("#"):
            level = len(line) - len(line.lstrip("#"))
            blocks.append((f"h{min(level, 3)}", inline(line[level:].strip())))
            i += 1
            continue
        if line.startswith("- "):
            items = []
            while i < len(lines) and lines[i].startswith("- "):
                items.append(inline(lines[i][2:].strip()))
                i += 1
            blocks.append(("list", items))
            continue
        paragraph = [line.strip()]
        i += 1
        while i < len(lines) and lines[i].strip() and not lines[i].startswith(("#", "|", "- ", "```")):
            paragraph.append(lines[i].strip())
            i += 1
        blocks.append(("p", inline(" ".join(paragraph))))
    return blocks


def build():
    font = register_font()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="Tiny Second-hand Shopping Platform 개발 보고서",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="KTitle", fontName=font, fontSize=20, leading=26, spaceAfter=12, textColor=colors.HexColor("#0f766e")))
    styles.add(ParagraphStyle(name="KH1", fontName=font, fontSize=16, leading=22, spaceBefore=12, spaceAfter=8, textColor=colors.HexColor("#17202a")))
    styles.add(ParagraphStyle(name="KH2", fontName=font, fontSize=13, leading=18, spaceBefore=9, spaceAfter=6, textColor=colors.HexColor("#17202a")))
    styles.add(ParagraphStyle(name="KP", fontName=font, fontSize=9.3, leading=14, spaceAfter=5))
    styles.add(ParagraphStyle(name="KCode", fontName=font, fontSize=8, leading=11, backColor=colors.HexColor("#f2f4f7"), borderPadding=5, spaceAfter=6))
    styles.add(ParagraphStyle(name="KList", fontName=font, fontSize=9, leading=13, leftIndent=8, firstLineIndent=-6, spaceAfter=3))

    story = []
    for kind, payload in parse_markdown(SOURCE.read_text(encoding="utf-8").splitlines()):
        if kind == "h1":
            if story:
                story.append(PageBreak())
            story.append(Paragraph(payload, styles["KTitle"]))
        elif kind == "h2":
            story.append(Paragraph(payload, styles["KH1"]))
        elif kind == "h3":
            story.append(Paragraph(payload, styles["KH2"]))
        elif kind == "p":
            story.append(Paragraph(payload, styles["KP"]))
        elif kind == "code":
            story.append(Paragraph(payload, styles["KCode"]))
        elif kind == "list":
            for item in payload:
                story.append(Paragraph(f"- {item}", styles["KList"]))
            story.append(Spacer(1, 2 * mm))
        elif kind == "table":
            if not payload:
                continue
            col_count = max(len(row) for row in payload)
            normalized = [row + [""] * (col_count - len(row)) for row in payload]
            table = Table(
                [[Paragraph(cell, styles["KP"]) for cell in row] for row in normalized],
                repeatRows=1,
                hAlign="LEFT",
            )
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e6f4f1")),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d5dd")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 4),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            story.append(table)
            story.append(Spacer(1, 4 * mm))
    doc.build(story)
    print(OUTPUT)


if __name__ == "__main__":
    build()
