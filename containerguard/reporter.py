import json

from rich.console import Console
from rich.table import Table
from rich import box

SEVERITY_SCORES = {
    "CRITICAL": 10,
    "HIGH":      7,
    "MEDIUM":    4,
    "LOW":       1,
}

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "orange1",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
}

# Risk label thresholds — based on cumulative score across all findings.
# A single CRITICAL (10) is LOW risk; multiple CRITICALs push into higher bands.
RISK_BANDS = [
    (0,  "NONE",     "green"),
    (10, "LOW",      "cyan"),
    (20, "MEDIUM",   "yellow"),
    (35, "HIGH",     "orange1"),
]
DEFAULT_RISK = ("CRITICAL", "bold red")


def _risk_label(total_score):
    """Map a cumulative score to a risk label and rich color string."""
    for threshold, label, color in reversed(RISK_BANDS):
        if total_score > threshold:
            return label, color
    if total_score == 0:
        return "NONE", "green"
    return DEFAULT_RISK


def _score_findings(findings):
    """Attach a numerical score to each finding dict. Returns (scored_list, total)."""
    total = 0
    scored = []
    for f in findings:
        score = SEVERITY_SCORES.get(f["severity"], 0)
        total += score
        scored.append({**f, "score": score})
    return scored, total


def build_report(findings, skipped=None, title="Findings"):
    """Build a JSON-serializable report dict from findings and skipped checks."""
    scored, total = _score_findings(findings)
    label, _ = _risk_label(total)
    return {
        "title": title,
        "findings": scored,
        "skipped": skipped or [],
        "count": len(findings),
        "total_score": total,
        "risk_level": label,
    }


def print_findings_json(findings, skipped=None, title="Findings"):
    """Emit findings as a single JSON object on stdout. Returns the total score."""
    report = build_report(findings, skipped, title)
    print(json.dumps(report, indent=2))
    return report["total_score"]


def emit_findings(findings, skipped=None, title="Findings", output="table"):
    """Render findings in the requested format ('table' or 'json')."""
    if output == "json":
        return print_findings_json(findings, skipped, title)
    return print_findings_table(findings, skipped, title)


def print_findings_table(findings, skipped=None, title="Findings"):
    """
    Render a color-coded findings table to the terminal using rich.
    Returns the total risk score (int) so callers can use it for
    exit codes or JSON output later.
    """
    console = Console()

    if not findings:
        console.print("\n[green]✓ No issues found.[/green]")
        _print_skipped(console, skipped)
        return 0

    scored, total = _score_findings(findings)
    label, label_color = _risk_label(total)

    table = Table(
        title=f"\n {title}",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
        border_style="dim",
    )

    table.add_column("ID",       style="dim",  width=9)
    table.add_column("Severity",               width=10)
    table.add_column("Score",    justify="right", width=6)
    table.add_column("Title",                  width=42)
    table.add_column("CIS Rule",               width=9)

    for f in scored:
        color = SEVERITY_COLORS.get(f["severity"], "white")
        table.add_row(
            f["id"],
            f"[{color}]{f['severity']}[/{color}]",
            f"[{color}]{f['score']}[/{color}]",
            f["title"],
            f["cis_rule"],
        )

    console.print(table)
    console.print(f"  Findings:         {len(findings)}")
    console.print(f"  Total risk score: [{label_color}]{total}[/{label_color}]")
    console.print(f"  Risk level:       [{label_color}]{label}[/{label_color}]\n")

    _print_skipped(console, skipped)
    return total


def _print_skipped(console, skipped):
    """Print skipped checks below the findings table."""
    if not skipped:
        return
    console.print("── Skipped Checks ────────────────────────")
    for s in skipped:
        console.print(f"  [dim]{s['id']}:[/dim] {s['reason']}")
    console.print()


# ── PDF report ────────────────────────────────────────────────────────────

# Severity → reportlab color name, used for the findings-table severity cells.
PDF_SEVERITY_HEX = {
    "CRITICAL": "#c0392b",  # red
    "HIGH":     "#e67e22",  # orange
    "MEDIUM":   "#d4ac0d",  # gold
    "LOW":      "#2980b9",  # blue
}

# Risk label → reportlab color, mirrors RISK_BANDS above.
PDF_RISK_HEX = {
    "NONE":     "#27ae60",
    "LOW":      "#2980b9",
    "MEDIUM":   "#d4ac0d",
    "HIGH":     "#e67e22",
    "CRITICAL": "#c0392b",
}


def _severity_counts(findings):
    """Return an ordered {severity: count} dict for the executive summary."""
    counts = {s: 0 for s in SEVERITY_SCORES}
    for f in findings:
        if f["severity"] in counts:
            counts[f["severity"]] += 1
    return counts


def build_dockerfile_diff(original_lines, hardened_lines,
                          fromfile="Dockerfile", tofile="Dockerfile.hardened"):
    """
    Produce a clean unified-diff string suitable for render_pdf().

    Accepts line lists that may or may not carry trailing newlines and always
    returns a single newline-joined string with no doubled blank lines (the
    common difflib pitfall).
    """
    import difflib

    orig = [ln.rstrip("\n") for ln in original_lines]
    new = [ln.rstrip("\n") for ln in hardened_lines]
    return "\n".join(difflib.unified_diff(
        orig, new, fromfile=fromfile, tofile=tofile, lineterm="",
    ))


def _diff_flowable(diff_text, styles):
    """
    Render a unified-diff string as a color-coded, whitespace-preserving
    flowable. Added lines are green, removed red, hunk headers cyan.
    """
    from xml.sax.saxutils import escape
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import XPreformatted

    mono = ParagraphStyle(
        "Diff",
        fontName="Courier",
        fontSize=7.5,
        leading=9.5,
    )

    # XPreformatted preserves whitespace but does not wrap, so hard-wrap long
    # lines ourselves to stop them clipping off the page. ~110 Courier chars
    # fit the default letter text width at 7.5pt.
    wrap_at = 110

    def _color_for(line):
        if line.startswith("+") and not line.startswith("+++"):
            return "#27ae60"
        if line.startswith("-") and not line.startswith("---"):
            return "#c0392b"
        if line.startswith("@@"):
            return "#2980b9"
        return "#555555"

    colored = []
    for line in diff_text.splitlines():
        color = _color_for(line)
        # Break the raw line into width-limited chunks before escaping.
        chunks = [line[i:i + wrap_at] for i in range(0, len(line), wrap_at)] or [""]
        for chunk in chunks:
            colored.append(f'<font color="{color}">{escape(chunk)}</font>')

    return XPreformatted("\n".join(colored), mono)


def _findings_table_flowables(scored, rl, styles):
    """
    Build the flowables for one findings table (header + rows), or a
    "no issues" line when empty. `rl` is a namespace of reportlab objects.
    """
    body = styles["body"]
    cell = styles["cell"]
    cell_head = styles["cell_head"]

    if not scored:
        return [rl.Paragraph("No issues found.", body)]

    header = [
        rl.Paragraph("ID", cell_head),
        rl.Paragraph("Severity", cell_head),
        rl.Paragraph("Description", cell_head),
        rl.Paragraph("Fix", cell_head),
    ]
    data = [header]
    row_styles = []
    for i, f in enumerate(scored, start=1):
        sev = f["severity"]
        sev_hex = PDF_SEVERITY_HEX.get(sev, "#555555")
        cis = f.get("cis_rule")
        id_text = f["id"] + (f'<br/><font size="6">CIS {cis}</font>' if cis else "")
        data.append([
            rl.Paragraph(id_text, cell),
            rl.Paragraph(f'<b><font color="{sev_hex}">{sev}</font></b>', cell),
            rl.Paragraph(f.get("description", ""), cell),
            rl.Paragraph(f.get("remediation", ""), cell),
        ])
        if i % 2 == 0:
            row_styles.append(
                ("BACKGROUND", (0, i), (-1, i), rl.colors.HexColor("#f5f5f5"))
            )

    table = rl.Table(
        data,
        colWidths=[0.85 * rl.inch, 0.75 * rl.inch, 2.9 * rl.inch, 2.6 * rl.inch],
        repeatRows=1,
    )
    table.setStyle(rl.TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), rl.colors.HexColor("#2c3e50")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, rl.colors.HexColor("#cccccc")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        *row_styles,
    ]))
    return [table]


def _render_document(out_path, title, sections, dockerfile_diff=None):
    """
    Shared PDF core. `sections` is a list of dicts, each:
        {"heading": str, "findings": [...], "skipped": [...] or None}

    The executive summary and risk band aggregate ALL findings across every
    section; each section then gets its own findings table. Returns out_path.
    """
    import types
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    )

    # Bundle reportlab objects so the flowable helpers stay import-free.
    rl = types.SimpleNamespace(
        colors=colors, inch=inch,
        Paragraph=Paragraph, Spacer=Spacer, Table=Table, TableStyle=TableStyle,
    )

    sheet = getSampleStyleSheet()
    body = sheet["BodyText"]
    cell = ParagraphStyle("Cell", parent=body, fontSize=8, leading=10)
    cell_head = ParagraphStyle(
        "CellHead", parent=cell, textColor=colors.white, fontName="Helvetica-Bold",
    )
    styles = {"body": body, "cell": cell, "cell_head": cell_head}

    # Aggregate across all sections for the summary + risk band.
    all_findings = [f for s in sections for f in s["findings"]]
    _, total = _score_findings(all_findings)
    label, _ = _risk_label(total)
    counts = _severity_counts(all_findings)
    risk_hex = PDF_RISK_HEX.get(label, "#c0392b")
    breakdown = ", ".join(
        f"{n} {sev.lower()}" for sev, n in counts.items() if n
    ) or "none"

    doc = SimpleDocTemplate(
        out_path, pagesize=letter,
        topMargin=0.7 * inch, bottomMargin=0.7 * inch,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
        title=title,
    )
    story = []

    # ── Title ──
    story.append(Paragraph(title, sheet["Title"]))
    story.append(Spacer(1, 6))

    # ── Executive summary ──
    story.append(Paragraph("Executive Summary", sheet["Heading2"]))
    lead = (
        f"This report combines <b>{len(sections)}</b> scans and identified"
        if len(sections) > 1 else "This scan identified"
    )
    summary = (
        f"{lead} <b>{len(all_findings)}</b> security "
        f"finding(s) ({breakdown}). The cumulative risk score is "
        f"<b>{total}</b>, placing this target at "
        f'<b><font color="{risk_hex}">{label}</font></b> risk. '
        f"Each finding below lists its remediation. Findings are mapped to "
        f"CIS Docker Benchmark rules where applicable."
    )
    story.append(Paragraph(summary, body))
    story.append(Spacer(1, 10))

    # ── Risk score band ──
    risk_tbl = Table(
        [[Paragraph(f'<font color="white"><b>RISK LEVEL: {label}</b></font>', body),
          Paragraph(f'<font color="white"><b>SCORE: {total}</b></font>', body)]],
        colWidths=[3.55 * inch, 3.55 * inch],
    )
    risk_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(risk_hex)),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
    ]))
    story.append(risk_tbl)
    story.append(Spacer(1, 14))

    # ── Per-section findings ──
    for section in sections:
        scored, _ = _score_findings(section["findings"])
        story.append(Paragraph(section["heading"], sheet["Heading2"]))
        story.extend(_findings_table_flowables(scored, rl, styles))

        skipped = section.get("skipped")
        if skipped:
            story.append(Spacer(1, 8))
            story.append(Paragraph("Skipped Checks", sheet["Heading3"]))
            for s in skipped:
                story.append(Paragraph(f"<b>{s['id']}:</b> {s['reason']}", cell))
        story.append(Spacer(1, 12))

    # ── Dockerfile diff ──
    if dockerfile_diff and dockerfile_diff.strip():
        story.append(Paragraph("Dockerfile Diff (original → hardened)",
                               sheet["Heading2"]))
        story.append(_diff_flowable(dockerfile_diff, sheet))

    doc.build(story)
    return out_path


def render_pdf(findings, out_path, skipped=None, title="ContainerGuard Report",
               dockerfile_diff=None):
    """
    Render a single-scan PDF report: executive summary, findings table
    (ID / severity / description / fix), risk score, and — when supplied —
    a color-coded Dockerfile diff.

    Returns out_path.
    """
    sections = [{
        "heading": "Findings",
        "findings": findings,
        "skipped": skipped or [],
    }]
    return _render_document(out_path, title, sections, dockerfile_diff)


def render_combined_pdf(sections, out_path, title="ContainerGuard Combined Report"):
    """
    Render one PDF covering multiple scans. `sections` is a list of
    (heading, findings, skipped) tuples. The executive summary and risk score
    aggregate findings across every section; each section keeps its own table.

    Returns out_path.
    """
    normalized = [
        {"heading": heading, "findings": findings, "skipped": skipped or []}
        for heading, findings, skipped in sections
    ]
    return _render_document(out_path, title, normalized)
