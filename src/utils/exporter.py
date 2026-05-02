import csv
import io
import json
from datetime import datetime

from src.database.db import get_cves, get_exploits, get_news, get_report_by_id
from src.utils.statistics import get_summary_stats, get_top_cwe, get_cvss_distribution


def export_cves_csv(limit: int = 5000) -> str:
    rows = get_cves(limit=limit)
    output = io.StringIO()
    fields = ["id", "published", "description", "cvss_score", "severity", "cwe"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def export_exploits_csv(limit: int = 5000) -> str:
    rows = get_exploits(limit=limit)
    output = io.StringIO()
    fields = ["id", "title", "link", "published", "cve_id", "platform", "exploit_type"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def export_news_csv(limit: int = 1000) -> str:
    rows = get_news(limit=limit)
    output = io.StringIO()
    fields = ["id", "title", "link", "published", "source", "summary"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def export_report_json(report_id: int) -> str:
    report = get_report_by_id(report_id)
    if not report:
        return json.dumps({"error": "Report not found"})
    stats = get_summary_stats()
    payload = {
        "report":     report,
        "generated":  datetime.utcnow().isoformat(),
        "stats":      stats,
        "top_cwe":    get_top_cwe(10),
        "cvss_dist":  get_cvss_distribution(),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def export_full_snapshot_json() -> str:
    stats   = get_summary_stats()
    cves    = get_cves(limit=500)
    exploits = get_exploits(limit=200)
    payload = {
        "generated":  datetime.utcnow().isoformat(),
        "stats":      stats,
        "top_cwe":    get_top_cwe(10),
        "cvss_dist":  get_cvss_distribution(),
        "cves":       cves,
        "exploits":   exploits,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def generate_text_report(report_id: int) -> str:
    report = get_report_by_id(report_id)
    if not report:
        return "Отчёт не найден"

    lines = [
        "=" * 60,
        f"  ОТЧЁТ: {report['title']}",
        "=" * 60,
        f"  Сформирован: {report['created_at'][:16]}",
        f"  Автор:       {report.get('author', '—')}",
        f"  Период:      {report.get('date_from','—')} — {report.get('date_to','—')}",
        "-" * 60,
        "  СТАТИСТИКА УЯЗВИМОСТЕЙ",
        "-" * 60,
        f"  Всего CVE:      {report['total_cves']}",
        f"  CRITICAL:       {report['critical']}",
        f"  HIGH:           {report['high']}",
        f"  MEDIUM:         {report['medium']}",
        f"  LOW:            {report['low']}",
        "-" * 60,
    ]
    if report.get("notes"):
        lines += ["  ПРИМЕЧАНИЯ", "-" * 60, f"  {report['notes']}", "-" * 60]

    top_cwe = get_top_cwe(5)
    if top_cwe:
        lines.append("  ТОП-5 ТИПОВ УЯЗВИМОСТЕЙ (CWE)")
        lines.append("-" * 60)
        for i, item in enumerate(top_cwe, 1):
            lines.append(f"  {i}. {item['cwe']}: {item['count']} CVE")
        lines.append("-" * 60)

    cvss = get_cvss_distribution()
    lines.append("  РАСПРЕДЕЛЕНИЕ CVSS SCORE")
    lines.append("-" * 60)
    for bucket, count in cvss.items():
        lines.append(f"  {bucket}: {count}")
    lines.append("=" * 60)

    return "\n".join(lines)


def build_pdf_report(report_id: int) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        )

        report = get_report_by_id(report_id)
        if not report:
            return b""

        buffer = io.BytesIO()
        doc    = SimpleDocTemplate(buffer, pagesize=A4,
                                   leftMargin=2*cm, rightMargin=2*cm,
                                   topMargin=2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("Title2", parent=styles["Title"],
                                     fontSize=16, textColor=colors.HexColor("#1a1a2e"),
                                     spaceAfter=6)
        h2_style = ParagraphStyle("H2", parent=styles["Heading2"],
                                  fontSize=12, textColor=colors.HexColor("#16213e"),
                                  spaceBefore=12, spaceAfter=4)
        body_style = ParagraphStyle("Body", parent=styles["Normal"],
                                    fontSize=10, leading=14)
        meta_style = ParagraphStyle("Meta", parent=styles["Normal"],
                                    fontSize=9, textColor=colors.grey)

        story = []
        story.append(Paragraph(f"Отчёт: {report['title']}", title_style))
        story.append(Paragraph(
            f"Сформирован: {report['created_at'][:16]} | "
            f"Автор: {report.get('author','—')} | "
            f"Период: {report.get('date_from','—')} — {report.get('date_to','—')}",
            meta_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey, spaceAfter=8))

        story.append(Paragraph("Статистика уязвимостей", h2_style))
        sev_data = [
            ["Уровень", "Количество", "Доля"],
            ["CRITICAL", str(report["critical"]),
             f"{report['critical']/max(report['total_cves'],1)*100:.1f}%"],
            ["HIGH",     str(report["high"]),
             f"{report['high']/max(report['total_cves'],1)*100:.1f}%"],
            ["MEDIUM",   str(report["medium"]),
             f"{report['medium']/max(report['total_cves'],1)*100:.1f}%"],
            ["LOW",      str(report["low"]),
             f"{report['low']/max(report['total_cves'],1)*100:.1f}%"],
            ["Всего",    str(report["total_cves"]), "100%"],
        ]
        sev_colors_map = {
            "CRITICAL": colors.HexColor("#f85149"),
            "HIGH":     colors.HexColor("#e3b341"),
            "MEDIUM":   colors.HexColor("#3fb950"),
            "LOW":      colors.HexColor("#58a6ff"),
            "Всего":    colors.HexColor("#444"),
        }
        t = Table(sev_data, colWidths=[5*cm, 4*cm, 4*cm])
        ts = TableStyle([
            ("BACKGROUND",  (0,0), (-1,0), colors.HexColor("#1c2128")),
            ("TEXTCOLOR",   (0,0), (-1,0), colors.white),
            ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 10),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f5f5f5")]),
            ("GRID",        (0,0), (-1,-1), 0.5, colors.lightgrey),
            ("ALIGN",       (1,0), (-1,-1), "CENTER"),
        ])
        t.setStyle(ts)
        story.append(t)
        story.append(Spacer(1, 12))

        top_cwe = get_top_cwe(10)
        if top_cwe:
            story.append(Paragraph("Топ-10 типов уязвимостей (CWE)", h2_style))
            cwe_data = [["CWE", "Количество CVE"]] + [[r["cwe"], str(r["count"])] for r in top_cwe]
            ct = Table(cwe_data, colWidths=[8*cm, 5*cm])
            ct.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1c2128")),
                ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
                ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",   (0,0), (-1,-1), 9),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f5f5f5")]),
                ("GRID",       (0,0), (-1,-1), 0.5, colors.lightgrey),
                ("ALIGN",      (1,0), (-1,-1), "CENTER"),
            ]))
            story.append(ct)
            story.append(Spacer(1, 12))

        cvss = get_cvss_distribution()
        story.append(Paragraph("Распределение по CVSS Score", h2_style))
        cvss_data = [["Диапазон CVSS", "Количество CVE"]] + [[k, str(v)] for k, v in cvss.items()]
        cvt = Table(cvss_data, colWidths=[8*cm, 5*cm])
        cvt.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1c2128")),
            ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f5f5f5")]),
            ("GRID",       (0,0), (-1,-1), 0.5, colors.lightgrey),
            ("ALIGN",      (1,0), (-1,-1), "CENTER"),
        ]))
        story.append(cvt)

        if report.get("notes"):
            story.append(Spacer(1, 12))
            story.append(Paragraph("Примечания", h2_style))
            story.append(Paragraph(report["notes"], body_style))

        doc.build(story)
        return buffer.getvalue()

    except ImportError:
        text = generate_text_report(report_id)
        return text.encode("utf-8")
