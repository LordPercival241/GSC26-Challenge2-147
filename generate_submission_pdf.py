import os
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT

def build_pdf(filename="submission.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    primary_color = colors.HexColor("#0C2C4E")    # Deep Navy
    secondary_color = colors.HexColor("#F9A200")  # IEEE Gold/Orange
    dark_neutral = colors.HexColor("#1E293B")     # Slate 800
    light_bg = colors.HexColor("#F8FAFC")         # Slate 50
    border_color = colors.HexColor("#CBD5E1")     # Slate 300

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=primary_color,
        alignment=TA_CENTER,
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=secondary_color,
        alignment=TA_CENTER,
        spaceAfter=15
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=primary_color,
        spaceBefore=14,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=dark_neutral,
        alignment=TA_JUSTIFY,
        spaceAfter=6
    )

    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0F172A"),
        backColor=colors.HexColor("#F1F5F9"),
        borderPadding=4,
        spaceAfter=6
    )

    story = []

    # Title & Banner
    story.append(Paragraph("IEEE Computer Society 2026 Global Student Challenge", subtitle_style))
    story.append(Paragraph("Challenge 2 Technical Submission Report", title_style))
    story.append(Paragraph("<b>Automated Vulnerability Detection & Remediation in GitHub Actions CI/CD Workflows</b>", ParagraphStyle('Sub', parent=subtitle_style, fontSize=11, textColor=primary_color)))
    story.append(HRFlowable(width="100%", thickness=2, color=secondary_color, spaceAfter=12))

    # Metadata Box Table
    meta_data = [
        [Paragraph("<b>Team ID:</b> 147", body_style), Paragraph("<b>Target Track:</b> Challenge 2 (GitHub Actions Security)", body_style)],
        [Paragraph("<b>Members:</b> Dante Aliguere Olivas Huamán & Lely Nicole Fernández Risco", body_style), Paragraph("<b>OpenRouter Model:</b> <code>anthropic/claude-3.5-sonnet</code>", body_style)]
    ]
    t_meta = Table(meta_data, colWidths=[250, 254])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), light_bg),
        ('BOX', (0,0), (-1,-1), 1, border_color),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 10))

    # Section 1: Executive Summary & Overall Approach
    story.append(Paragraph("1. Executive Summary & Methodology Overview", h1_style))
    story.append(Paragraph(
        "GitHub Actions has emerged as a critical infrastructure layer in modern software engineering. "
        "However, unsafe handling of untrusted context variables (e.g., <code>github.head_ref</code>, "
        "<code>github.event.issue.title</code>) in unquoted <code>run:</code> shell steps introduces severe "
        "Command Injection vulnerabilities. Our solution (<b>Q-Suyo-Guard</b>) provides a fully automated, "
        "deterministic static analysis and taint-tracking pipeline coupled with an automated patch generation engine "
        "integrated with OpenRouter API for LLM-assisted patch explanations.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Core Design Principles:</b><br/>"
        "1. <b>Zero False Positives:</b> Strict scoping against the official <code>untrusted_data.csv</code> catalog.<br/>"
        "2. <b>Cross-Component SHA Resolution:</b> Recursively resolves nested composite actions and reusable workflows pinned by 12-character commit SHAs.<br/>"
        "3. <b>First-Exploitable-Sink Reporting:</b> Strictly enforces the competition Task 1 detection constraint (reporting the earliest sink per taint flow).<br/>"
        "4. <b>Complete Flow Remediation:</b> Enforces Task 2 patching rules by sanitizing both initial and downstream re-consumptions of untrusted variables.",
        body_style
    ))

    # Section 2: Vulnerability Detection Methodology (Task 1)
    story.append(Paragraph("2. Vulnerability Detection Methodology (Task 1)", h1_style))
    story.append(Paragraph(
        "Our detection engine operates in three systematic stages:",
        body_style
    ))
    story.append(Paragraph(
        "<b>Stage A — Untrusted Context Cataloging:</b> We load <code>untrusted_data.csv</code> and compile "
        "optimized regular expressions supporting exact contexts as well as wildcard expressions (e.g., <code>github.event.commits[*].message</code>).",
        body_style
    ))
    story.append(Paragraph(
        "<b>Stage B — Multi-Component Graph Resolution:</b> When a workflow references external components via <code>uses:</code> "
        "(e.g., <code>tj-actions/branch-names@9cd06d955f41</code>), the loader maps the reference to local vendored paths:<br/>"
        "• <i>Composite Actions:</i> <code>actions/&lt;owner&gt;/&lt;repo&gt;/&lt;sha[:12]&gt;/[subpath]/action.yml</code><br/>"
        "• <i>Reusable Workflows:</i> <code>reusable_workflows/&lt;owner&gt;/&lt;repo&gt;/&lt;sha[:12]&gt;/.github/workflows/&lt;file&gt;.yml</code>",
        body_style
    ))
    story.append(Paragraph(
        "<b>Stage C — Taint & Line-Accurate Sink Detection:</b> The scanner parses expressions matching <code>${{ &lt;expr&gt; }}</code> "
        "inside shell execution blocks. It identifies the origin line (<code>from</code>) and pinpoints the exact starting line of the <code>run:</code> step (<code>to</code>).",
        body_style
    ))

    # Section 3: Patch Generation Methodology (Task 2)
    story.append(Paragraph("3. Automated Patch Generation Methodology (Task 2)", h1_style))
    story.append(Paragraph(
        "To eliminate code injection while strictly preserving workflow execution logic, our patcher applies the canonical environment variable isolation pattern:",
        body_style
    ))
    
    code_example = (
        "<b>Vulnerable Pattern:</b><br/>"
        "&nbsp;&nbsp;- name: Verify Branch<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;run: echo \"Running on branch ${{ github.head_ref }}\"<br/><br/>"
        "<b>Sanitized Patch Output:</b><br/>"
        "&nbsp;&nbsp;- name: Verify Branch<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;env:<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HEAD_REF: ${{ github.head_ref }}<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;run: echo \"Running on branch $HEAD_REF\""
    )
    story.append(Paragraph(code_example, code_style))

    story.append(Paragraph(
        "<b>Key Patching Guarantees:</b><br/>"
        "• <b>Unified Diff Format:</b> Outputs standard, <code>git apply</code>-compatible patch files saved to <code>patches/&lt;sample_id&gt;.patch</code>.<br/>"
        "• <b>Downstream Sanitization:</b> Identifies and sanitizes secondary re-consumptions of tainted variables (e.g., via <code>$GITHUB_ENV</code> or outputs) across all steps.<br/>"
        "• <b>Indentation & Syntax Integrity:</b> Preserves exact YAML line endings, quotes, and structural formatting.",
        body_style
    ))

    # Section 4: OpenRouter API & LLM Configuration
    story.append(Paragraph("4. OpenRouter API & Secure LLM Configuration", h1_style))
    story.append(Paragraph(
        "In strict compliance with organizer security specifications:<br/>"
        "• <b>Gateway Endpoint:</b> <code>https://openrouter.ai/api/v1/chat/completions</code><br/>"
        "• <b>Official Model Identifier:</b> <code>anthropic/claude-3.5-sonnet</code><br/>"
        "• <b>Secure Key Management:</b> Configured dynamically via environment variable <code>OPENROUTER_API_KEY</code> or CLI parameter <code>--api-key</code> (no plaintext key exposure in repository code).<br/>"
        "• <b>Role:</b> Generates precise natural-language explanations of remediated vulnerabilities within the generated patch metadata.",
        body_style
    ))

    # Section 5: Verification & Results
    story.append(Paragraph("5. Empirical Verification & Conclusion", h1_style))
    story.append(Paragraph(
        "Our framework was benchmarked against the official training dataset (<code>train.csv</code>). "
        "The automated detector achieved high precision and recall, correctly isolating single-file and cross-component vulnerabilities, "
        "and generating valid unified diffs that pass <code>git apply</code> verification checks without syntax errors.",
        body_style
    ))
    story.append(Spacer(1, 10))

    # Footer Sign-off
    story.append(HRFlowable(width="100%", thickness=1, color=border_color, spaceAfter=8))
    story.append(Paragraph("<b>Submitted by Team 147</b> — IEEE CS Global Student Challenge 2026", ParagraphStyle('Foot', parent=body_style, alignment=TA_CENTER, fontSize=8, textColor=colors.HexColor("#64748B"))))

    doc.build(story)
    print(f"Successfully generated {filename}")

if __name__ == "__main__":
    build_pdf()
