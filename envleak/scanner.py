"""Filesystem scanner. Everything here runs locally; nothing leaves the machine."""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .rules import (
    ALL_RULES, ASSIGNMENT, looks_like_code, looks_like_placeholder,
    shannon_entropy,
)

MAX_FILE_BYTES = 2 * 1024 * 1024  # skip anything bigger than 2 MB
MAX_LINE_LEN = 4000

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", ".nuxt", "target", "vendor", ".tox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages",
    ".terraform", "coverage", ".idea", ".gradle",
}

SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".pdf",
    ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar", ".jar",
    ".mp3", ".mp4", ".mov", ".avi", ".woff", ".woff2", ".ttf", ".otf",
    ".so", ".dylib", ".dll", ".exe", ".bin", ".pyc", ".pyo", ".class",
    ".lock", ".min.js", ".map",
}

# Config-shaped files. The generic entropy pass runs ONLY here: in source
# code it fires on ordinary expressions (key = key.upper()) and destroys
# the signal-to-noise ratio.
CONFIG_EXT = {".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
              ".conf", ".properties", ".tfvars"}

# Template files ship fake credentials on purpose.
EXAMPLE_MARKERS = (".example", ".sample", ".template", ".dist", "sample.",
                   "example.", "template.")


def is_example_file(name: str) -> bool:
    n = name.lower()
    return any(m in n for m in EXAMPLE_MARKERS)


# Files that are, by their nature, credential-bearing. Finding a live secret
# in one of these is worse because they're the ones that get committed or
# copied into images by accident.
HOT_FILES = {
    ".env", ".env.local", ".env.production", ".env.prod", ".env.dev",
    ".env.development", ".env.staging", ".envrc",
    "credentials", "config.json", "secrets.json", "settings.json",
    "docker-compose.yml", "docker-compose.yaml",
}

# The agent surface: MCP servers, orchestration configs, notebooks.
AGENT_FILE_HINTS = (
    "mcp.json", "mcp_config", "claude_desktop_config.json",
    "langgraph.json", "crew", "agents.yaml", "agent.yaml",
    ".n8n", "workflows", "flowise", "dify",
)

TEXT_HINT_EXT = {
    ".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash", ".zsh", ".fish",
    ".rb", ".go", ".rs", ".java", ".php", ".cs", ".txt", ".md", ".properties",
    ".tf", ".tfvars", ".xml", ".sql", ".ipynb", ".example", ".sample", "",
}


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    group: str
    path: str
    line_no: int
    snippet: str
    in_hot_file: bool = False
    gitignored: bool = False


@dataclass
class ScanResult:
    root: str
    findings: list = field(default_factory=list)
    files_scanned: int = 0
    env_files_found: list = field(default_factory=list)
    agent_files_found: list = field(default_factory=list)
    env_in_git: list = field(default_factory=list)
    has_gitignore: bool = False


def _redact(value: str) -> str:
    """Show enough to identify the key, never enough to use it."""
    v = value.strip().strip("'\"")
    if len(v) <= 10:
        return v[:2] + "*" * max(len(v) - 2, 0)
    return f"{v[:4]}{'*' * 8}{v[-4:]}"


def _redact_line(line: str, match_text: str) -> str:
    line = line.strip()[:MAX_LINE_LEN]
    return line.replace(match_text, _redact(match_text))[:200]


def _is_probably_text(path: Path) -> bool:
    if path.suffix.lower() in SKIP_EXT:
        return False
    if path.suffix.lower() in TEXT_HINT_EXT or path.name.startswith("."):
        return True
    return path.suffix == ""


def _read_gitignore(root: Path) -> set:
    patterns = set()
    gi = root / ".gitignore"
    if gi.exists():
        try:
            for line in gi.read_text(errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.add(line.rstrip("/"))
        except OSError:
            pass
    return patterns


def _matches_gitignore(rel: str, patterns: set) -> bool:
    name = os.path.basename(rel)
    for p in patterns:
        if p in (name, rel):
            return True
        if p.startswith("*") and name.endswith(p[1:]):
            return True
        if p.endswith("*") and name.startswith(p[:-1]):
            return True
        if rel.startswith(p + "/"):
            return True
    return False


def scan(root: str, max_files: int = 20000) -> ScanResult:
    root_path = Path(root).resolve()
    result = ScanResult(root=str(root_path))
    gitignore = _read_gitignore(root_path)
    result.has_gitignore = bool(gitignore)
    tracked = _git_tracked_files(root_path)

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if result.files_scanned >= max_files:
                return result
            fpath = Path(dirpath) / fname
            try:
                if fpath.is_symlink() or fpath.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            if not _is_probably_text(fpath):
                continue

            rel = str(fpath.relative_to(root_path))
            lower = rel.lower()

            is_example = is_example_file(fname)
            is_hot = (fname in HOT_FILES or fname.startswith(".env")) \
                and not is_example
            if is_hot:
                result.env_files_found.append(rel)
                if tracked is not None and rel in tracked:
                    result.env_in_git.append(rel)

            if any(h in lower for h in AGENT_FILE_HINTS):
                result.agent_files_found.append(rel)

            try:
                text = fpath.read_text(errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue
            result.files_scanned += 1

            ignored = _matches_gitignore(rel, gitignore)
            is_config = (fpath.suffix.lower() in CONFIG_EXT
                         or fname.startswith(".env"))
            _scan_text(text, rel, is_hot, ignored, result,
                       is_config=is_config, is_example=is_example)

    return result


def _git_tracked_files(root: Path):
    """Return set of git-tracked paths, or None if not a repo / git missing."""
    if not (root / ".git").exists():
        return None
    try:
        import subprocess
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files"],
            capture_output=True, text=True, timeout=20,
        )
        if out.returncode != 0:
            return None
        return set(out.stdout.splitlines())
    except Exception:
        return None


def _scan_text(text: str, rel: str, is_hot: bool, ignored: bool,
               result: ScanResult, is_config: bool = False,
               is_example: bool = False) -> None:
    seen = set()
    claimed = set()
    lines = text.splitlines()

    for i, line in enumerate(lines, 1):
        if len(line) > MAX_LINE_LEN:
            continue
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "<!--")) and "=" not in stripped:
            continue

        for rule in ALL_RULES:
            for m in rule.pattern.finditer(line):
                hit = m.group(1) if m.groups() else m.group(0)
                # One credential, one finding: the first (most specific) rule
                # to claim a value wins. ALL_RULES is ordered specific-first.
                claim = hit.strip().strip("'\"")[:60]
                if claim in claimed:
                    continue
                if looks_like_placeholder(hit):
                    continue
                claimed.add(claim)
                sev = "medium" if is_example else rule.severity
                result.findings.append(Finding(
                    rule_id=rule.id, rule_name=rule.name,
                    severity=sev, group=rule.group,
                    path=rel, line_no=i,
                    snippet=_redact_line(line, hit),
                    in_hot_file=is_hot, gitignored=ignored,
                ))

        # Generic entropy pass — config files only. In source code this
        # fires on ordinary expressions and buries the real findings.
        if not is_config:
            continue
        for m in ASSIGNMENT.finditer(line):
            varname, value = m.group(1), m.group(2)
            if looks_like_placeholder(value) or looks_like_code(value):
                continue
            if shannon_entropy(value) < 3.5:
                continue
            claim = value.strip().strip("'\"")[:60]
            if claim in claimed:
                continue
            if any(claim in c or c in claim for c in claimed):
                continue
            claimed.add(claim)
            result.findings.append(Finding(
                rule_id="high-entropy", rule_name=f"High-entropy value in {varname}",
                severity="medium", group="classic",
                path=rel, line_no=i,
                snippet=_redact_line(line, value),
                in_hot_file=is_hot, gitignored=ignored,
            ))
