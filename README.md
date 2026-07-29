# GSC26-Challenge2-147: Automated Detection and Patching of GitHub Actions Vulnerabilities
**IEEE Computer Society 2026 Global Student Challenge - Challenge 2**
**Team 147** — Dante Aliguere Olivas Huamán & Lely Nicole Fernández Risco

## Overview
This repository contains our official submission for **Challenge 2** of the IEEE Global Student Challenge 2026. The objective is to build an automated system capable of:
1. **Detecting code injection vulnerabilities** in GitHub Actions workflows, composite actions, and reusable workflows (when untrusted inputs flow into unquoted `run:` shell commands).
2. **Generating git-apply-compatible unified patches** that sanitize untrusted inputs via environment variables (`env:`) without breaking intended workflow logic.

---

## Repository Structure

```text
GSC26-Challenge2-147/
├── scanner/
│   ├── __init__.py         # Package initialization
│   ├── untrusted.py        # Untrusted input loader & pattern matching regex engine
│   ├── loader.py           # Dependency resolver for uses: SHA paths (actions & reusable workflows)
│   ├── detector.py         # Static taint tracking & sink detection in run: blocks
│   └── patcher.py          # Unified diff (.patch) generator applying canonical env-var pattern
├── run.py                  # Main execution entrypoint (generates test.csv & patches/)
├── evaluate.py             # Ground-truth evaluator (Precision, Recall, F1-Score)
├── requirements.txt        # Pinned Python dependencies (PyYAML, ruamel.yaml)
└── README.md               # Framework documentation
```

---

## Architecture & Technical Approach

### 1. Untrusted Input Identification (`scanner/untrusted.py`)
Parses `untrusted_data.csv` to build exact and wildcard regular expressions matching untrusted contexts (e.g., `github.head_ref`, `github.event.issue.title`, `github.event.commits[*].message`).

### 2. Cross-Component Resolution (`scanner/loader.py`)
Resolves referenced actions and reusable workflows pinned by SHA commit hashes to their offline vendored locations:
- **Actions**: `uses: <owner>/<repo>@<sha>` $\rightarrow$ `actions/<owner>/<repo>/<sha[:12]>/[subpath]/action.yml`
- **Reusable Workflows**: `uses: <owner>/<repo>/.github/workflows/<file>.yml@<sha>` $\rightarrow$ `reusable_workflows/<owner>/<repo>/<sha[:12]>/.github/workflows/<file>.yml`

### 3. Taint Tracking & Vulnerability Detection (`scanner/detector.py`)
Scans YAML files for `${{ <expr> }}` interpolations inside `run:` shell scripts. Identifies the source line (`from`) and the execution sink line (`to`).

### 4. Automated Patch Generation (`scanner/patcher.py`)
Remediates code injection by applying the canonical environment variable isolation pattern:
```yaml
# BEFORE (Vulnerable):
- name: Run Script
  run: echo "${{ github.head_ref }}"

# AFTER (Sanitized Patch):
- name: Run Script
  env:
    HEAD_REF: ${{ github.head_ref }}
  run: echo "$HEAD_REF"
```
Generates standard unified diff files saved to `patches/<sample_id>.patch`.

---

## Usage Instructions

### Prerequisites & Installation
Ensure Python 3.10+ is installed, then install dependencies:
```bash
pip install -r requirements.txt
```

### Running Detection and Patching
To process input workflow samples and produce the final `test.csv` submission alongside patches in `patches/`:
```bash
python run.py --data-dir ../ --untrusted-csv ../untrusted_data.csv --input-csv ../train.csv --output-csv test.csv
```

### Performance Evaluation
To evaluate detection performance (Precision, Recall, F1) against `train.csv` ground truth:
```bash
python evaluate.py --predictions test.csv --ground-truth ../train.csv
```

---

## Team Information
- **Team ID:** 147
- **Members:** Dante Aliguere Olivas Huamán & Lely Nicole Fernández Risco
- **Challenge:** IEEE CS GSC 2026 — Challenge 2 (GitHub Actions Security)
