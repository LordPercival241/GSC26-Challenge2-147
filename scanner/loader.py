from pathlib import Path
import yaml

class YAMLLoader:
    def __init__(self, base_dir: str | Path):
        self.base_dir = Path(base_dir)

    def resolve_action_path(self, uses_string: str) -> Path | None:
        """
        Resuelve referencias uses: <owner>/<repo>@<sha> o <owner>/<repo>/<path>@<sha>
        Mapea a: actions/<owner>/<repo>/<sha[:12]>/[path]/action.{yml,yaml}
        """
        if "@" not in uses_string:
            return None
        
        target, sha = uses_string.split("@", 1)
        sha_short = sha[:12]
        parts = target.split("/")
        
        if len(parts) < 2:
            return None

        owner = parts[0]
        repo = parts[1]
        sub_path = "/".join(parts[2:]) if len(parts) > 2 else ""

        action_dir = self.base_dir / "actions" / owner / repo / sha_short
        if sub_path:
            action_dir = action_dir / sub_path

        for ext in ["action.yml", "action.yaml"]:
            candidate = action_dir / ext
            if candidate.exists():
                return candidate
        return None

    def resolve_reusable_workflow_path(self, uses_string: str) -> Path | None:
        """
        Resuelve referencias uses: <owner>/<repo>/.github/workflows/<file>.yml@<sha>
        Mapea a: reusable_workflows/<owner>/<repo>/<sha[:12]>/.github/workflows/<file>.yml
        """
        if "@" not in uses_string:
            return None
        
        target, sha = uses_string.split("@", 1)
        sha_short = sha[:12]
        parts = target.split("/")

        if len(parts) < 2:
            return None

        owner = parts[0]
        repo = parts[1]
        rel_workflow_path = "/".join(parts[2:])

        candidate = self.base_dir / "reusable_workflows" / owner / repo / sha_short / rel_workflow_path
        if candidate.exists():
            return candidate
        return None

    def load_yaml(self, path: Path) -> dict | None:
        if not path.exists():
            return None
        with open(path, "r", encoding="utf-8") as f:
            try:
                return yaml.safe_load(f)
            except yaml.YAMLError:
                return None

    def read_raw_lines(self, path: Path) -> list[str]:
        if not path.exists():
            return []
        with open(path, "r", encoding="utf-8") as f:
            return f.readlines()
