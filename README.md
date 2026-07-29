# GSC26-Challenge2-147: Automated Detection and Patching of GitHub Actions Vulnerabilities
**IEEE Computer Society 2026 Global Student Challenge — Challenge 2**
**Team 147** — Dante Aliguere Olivas Huamán & Lely Nicole Fernández Risco

## Overview
This repository contains our complete submission for **Challenge 2** of the IEEE Global Student Challenge 2026. The objective is to construct an automated system capable of:
1. **Detecting code injection vulnerabilities** in GitHub Actions workflows, composite actions, and reusable workflows (when untrusted context inputs reach unquoted `run:` shell execution steps).
2. **Generating git-apply-compatible unified patches** that sanitize untrusted inputs via step-level environment variables (`env:`) while strictly preserving workflow execution logic.

---

## Deliverables & Repository Structure

```text
GSC26-Challenge2-147/
├── scanner/
│   ├── __init__.py         # Package initialization
│   ├── untrusted.py        # Untrusted input loader & wildcard pattern matching engine
│   ├── loader.py           # Dependency resolver for uses: SHA paths (actions & reusable workflows)
│   ├── detector.py         # Static taint tracking & line-accurate sink detection
│   └── patcher.py          # Unified diff (.patch) generator applying canonical env-var pattern
├── run.py                  # Main execution entrypoint (generates test.csv & patches/)
├── evaluate.py             # Evaluation module (Precision, Recall, F1-Score)
├── generate_submission_pdf.py # Technical report generator (compiles submission.pdf)
├── submission.pdf          # Official technical report PDF required for final submission
├── requirements.txt        # Pinned Python dependencies
├── .gitignore              # Repository git exclusion rules
└── README.md               # Framework documentation
```

---

## Technical Architecture & Methodology

### 1. Untrusted Input Identification (`scanner/untrusted.py`)
Parses `untrusted_data.csv` to compile exact and wildcard regular expressions matching untrusted GitHub contexts (e.g., `github.head_ref`, `github.event.issue.title`, `github.event.commits[*].message`).

### 2. Cross-Component Resolution (`scanner/loader.py`)
Resolves referenced composite actions and reusable workflows pinned by SHA commit hashes to their offline vendored paths:
- **Composite Actions**: `uses: <owner>/<repo>@<sha>` $\rightarrow$ `actions/<owner>/<repo>/<sha[:12]>/[subpath]/action.yml`
- **Reusable Workflows**: `uses: <owner>/<repo>/.github/workflows/<file>.yml@<sha>` $\rightarrow$ `reusable_workflows/<owner>/<repo>/<sha[:12]>/.github/workflows/<file>.yml`

### 3. Taint Tracking & First-Sink Detection (`scanner/detector.py`)
Scans YAML files for `${{ <expr> }}` interpolations inside `run:` shell execution blocks. Identifies the source line (`from`) and pinpoints the exact starting line of the earliest vulnerable `run:` step (`to`), strictly adhering to the competition's Task 1 detection rule (first exploitable sink per taint flow).

### 4. Complete-Flow Automated Patching (`scanner/patcher.py`)
Enforces Task 2 patching rules by sanitizing both initial and downstream re-consumptions of untrusted variables. It applies the canonical step-level environment variable encapsulation pattern:
```yaml
# BEFORE (Vulnerable):
- name: Verify Branch
  run: echo "Branch name is ${{ github.head_ref }}"

# AFTER (Sanitized Patch):
- name: Verify Branch
  env:
    HEAD_REF: ${{ github.head_ref }}
  run: echo "Branch name is $HEAD_REF"
```
Outputs standard, unified diff files saved to `patches/<sample_id>.patch` (exactly one `.patch` file per vulnerable sample).

---

## Execution & Usage Instructions

### 1. Installation & Environment
Requires Python 3.10 or higher. Install all pinned dependencies:
```bash
pip install -r requirements.txt
```

### 2. Running Automated Vulnerability Detection & Patch Generation
To process samples (e.g., test or validation set) and generate `test.csv` and the `patches/` directory:
```bash
# General usage for hidden test evaluation
python run.py --data-dir ../ --split test --output-csv test.csv --patches-dir patches

# Running on training dataset
python run.py --data-dir ../ --split train --input-csv ../train.csv --output-csv train_pred.csv
```

### 3. Evaluating Metrics
To evaluate precision, recall, and F1-score against ground truth:
```bash
python evaluate.py --predictions train_pred.csv --ground-truth ../train.csv
```

### 4. Regenerating Technical Report PDF (`submission.pdf`)
To recompile the official technical submission report PDF:
```bash
python generate_submission_pdf.py
```

---

## LLM & OpenRouter API Disclosure

In compliance with competition guidelines:
- **Primary Pipeline:** Our core detection and patch generation engine operates as a zero-latency, 100% deterministic static analysis & taint tracking system for absolute reproducibility.
- **LLM Integration Gateway:** OpenRouter API (`https://openrouter.ai/api/v1`).
- **Model Identifier:** `anthropic/claude-3.5-sonnet` (or `anthropic/claude-3.5-haiku` for lightweight explanations).
- **Environment Variable:** `OPENROUTER_API_KEY`.
- **Usage:** Optional enhancement for generating detailed natural-language explanations in patch metadata.

---

## Team Information
- **Team ID:** 147
- **Members:** Dante Aliguere Olivas Huamán & Lely Nicole Fernández Risco
- **Challenge:** IEEE CS GSC 2026 — Challenge 2 (GitHub Actions Security)
- **Repository:** [https://github.com/LordPercival241/GSC26-Challenge2-147](https://github.com/LordPercival241/GSC26-Challenge2-147)
