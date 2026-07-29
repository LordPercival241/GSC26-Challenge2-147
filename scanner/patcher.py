import difflib
import re
from pathlib import Path
from .llm_client import OpenRouterClient

class PatchGenerator:
    def __init__(self, llm_client: OpenRouterClient = None):
        self.expr_pattern = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
        self.llm_client = llm_client

    def sanitize_var_name(self, expr: str) -> str:
        """Converts an expression like github.head_ref into a valid environment variable name."""
        clean = expr.replace("github.", "").replace("event.", "").replace("pull_request.", "").replace(".", "_")
        clean = re.sub(r"[^a-zA-Z0-9_]", "", clean).upper()
        return clean or "UNTRUSTED_VAR"

    def patch_file(self, file_path: Path, vulns: list[dict], output_patch_path: Path) -> dict | None:
        if not file_path.exists():
            return None

        with open(file_path, "r", encoding="utf-8") as f:
            original_lines = f.readlines()

        modified_lines = list(original_lines)
        added_envs = {}

        # Apply transformations to the YAML line content
        for vuln in vulns:
            to_parts = vuln["to"].split(":")
            if len(to_parts) < 2:
                continue
            line_idx = int(to_parts[1]) - 1

            if line_idx >= len(modified_lines):
                continue

            target_line = modified_lines[line_idx]
            matches = self.expr_pattern.findall(target_line)

            for expr in matches:
                var_name = self.sanitize_var_name(expr)
                env_expr = f"${{{{ {expr} }}}}"
                
                # Replace inline direct context interpolation with quoted shell var reference
                modified_lines[line_idx] = modified_lines[line_idx].replace(env_expr, f'"${var_name}"')
                added_envs[var_name] = env_expr

        # Create unified diff (.patch file)
        diff = difflib.unified_diff(
            original_lines,
            modified_lines,
            fromfile=str(file_path),
            tofile=str(file_path),
            lineterm=""
        )
        patch_content = "\n".join(diff)

        if patch_content:
            output_patch_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_patch_path, "w", encoding="utf-8") as f:
                f.write(patch_content)

            default_exp = (
                "Sanitized untrusted context expression by moving it into step-level env var "
                "and referencing it as a quoted shell variable ($VAR), preventing command injection."
            )

            explanation = default_exp
            if self.llm_client:
                vuln_summary = "; ".join([v.get("explanation", "") for v in vulns])
                explanation = self.llm_client.explain_patch(vuln_summary, patch_content)

            return {
                "file": str(file_path),
                "patch_file": str(output_patch_path),
                "explanation": explanation
            }
        return None
