"""Scoring and the shareable scorecard."""

import json
from collections import Counter

WEIGHTS = {"critical": 25, "high": 10, "medium": 3}
HOT_FILE_MULTIPLIER = 1.5   # a secret sitting in .env / config is worse
GIT_TRACKED_PENALTY = 20    # .env committed to git

GRADES = [
    (0, "A", "Limpio"),
    (1, "B", "Menor"),
    (25, "C", "Atención"),
    (60, "D", "Riesgo alto"),
    (100, "F", "Crítico"),
]

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
COLORS = {
    "A": "\033[92m", "B": "\033[92m", "C": "\033[93m",
    "D": "\033[91m", "F": "\033[91m",
}
SEV_COLOR = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[94m"}


def compute_score(result) -> tuple:
    """Return (penalty_points, grade_letter, label)."""
    points = 0.0
    for f in result.findings:
        w = WEIGHTS.get(f.severity, 3)
        if f.in_hot_file:
            w *= HOT_FILE_MULTIPLIER
        if f.gitignored:
            w *= 0.5  # ignored by git = less likely to leak outward
        points += w
    points += GIT_TRACKED_PENALTY * len(result.env_in_git)

    grade, label = "A", "Limpio"
    for threshold, letter, text in GRADES:
        if points >= threshold:
            grade, label = letter, text
    return round(points), grade, label


def _bar(grade: str) -> str:
    filled = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}[grade]
    return "█" * filled + "░" * (5 - filled)


def render_terminal(result, color: bool = True) -> str:
    points, grade, label = compute_score(result)
    c = (lambda s, code: f"{code}{s}{RESET}") if color else (lambda s, code: s)
    gcol = COLORS[grade]

    sev = Counter(f.severity for f in result.findings)
    groups = Counter(f.group for f in result.findings)

    out = []
    out.append("")
    out.append(c("  ┌────────────────────────────────────────────┐", DIM))
    out.append(c("  │", DIM) + c("            E N V L E A K   S C A N         ", BOLD)
               + c(" │", DIM))
    out.append(c("  └────────────────────────────────────────────┘", DIM))
    out.append("")
    out.append(f"   {c(grade, gcol + BOLD)}   {c(_bar(grade), gcol)}   {c(label, BOLD)}")
    out.append("")
    out.append(f"   {len(result.findings)} hallazgo(s) en {result.files_scanned} archivos")
    if result.findings:
        parts = []
        for s in ("critical", "high", "medium"):
            if sev[s]:
                parts.append(c(f"{sev[s]} {s}", SEV_COLOR[s]))
        out.append("   " + "  ·  ".join(parts))
    out.append("")

    if groups.get("agent"):
        out.append(c(f"   ⚡ {groups['agent']} en la superficie de agentes/LLM", "\033[95m"))
        out.append("")

    if result.env_in_git:
        out.append(c("   ✗ ARCHIVOS DE ENTORNO RASTREADOS POR GIT:", "\033[91m" + BOLD))
        for p in result.env_in_git[:5]:
            out.append(c(f"     {p}", "\033[91m"))
        out.append("")

    if result.findings:
        out.append(c("   Hallazgos", BOLD))
        out.append("")
        shown = sorted(
            result.findings,
            key=lambda f: (
                {"critical": 0, "high": 1, "medium": 2}[f.severity],
                not f.in_hot_file,
            ),
        )
        for f in shown[:15]:
            tag = c(f.severity.upper()[:4], SEV_COLOR[f.severity])
            out.append(f"   {tag}  {c(f.rule_name, BOLD)}")
            out.append(c(f"         {f.path}:{f.line_no}", DIM))
            out.append(c(f"         {f.snippet}", DIM))
            out.append("")
        if len(shown) > 15:
            out.append(c(f"   … y {len(shown) - 15} más\n", DIM))
    else:
        out.append(c("   Sin credenciales expuestas. Bien ahí.\n", "\033[92m"))

    if not result.has_gitignore and result.env_files_found:
        out.append(c("   ! No hay .gitignore y existen archivos .env\n", "\033[93m"))

    out.append(c("   Nada de esto salió de tu máquina.", DIM))
    out.append("")
    return "\n".join(out)


def render_markdown(result) -> str:
    points, grade, label = compute_score(result)
    sev = Counter(f.severity for f in result.findings)
    groups = Counter(f.group for f in result.findings)

    lines = [
        "```",
        "  E N V L E A K   S C A N",
        "",
        f"   {grade}   {_bar(grade)}   {label}",
        "",
        f"   {len(result.findings)} hallazgo(s) · {result.files_scanned} archivos",
    ]
    if result.findings:
        parts = [f"{sev[s]} {s}" for s in ("critical", "high", "medium") if sev[s]]
        lines.append("   " + "  ·  ".join(parts))
    if groups.get("agent"):
        lines.append(f"   {groups['agent']} en la superficie de agentes/LLM")
    if result.env_in_git:
        lines.append(f"   {len(result.env_in_git)} archivo(s) .env rastreados por git")
    lines += ["```", "", "_Escaneado localmente con `pipx run envleak`. "
              "Ningún dato salió de la máquina._"]
    return "\n".join(lines)


def render_json(result) -> str:
    points, grade, label = compute_score(result)
    return json.dumps({
        "grade": grade,
        "label": label,
        "penalty_points": points,
        "files_scanned": result.files_scanned,
        "env_files_tracked_by_git": result.env_in_git,
        "agent_config_files": result.agent_files_found,
        "findings": [
            {
                "rule": f.rule_id,
                "name": f.rule_name,
                "severity": f.severity,
                "group": f.group,
                "path": f.path,
                "line": f.line_no,
                "snippet": f.snippet,
                "in_env_or_config_file": f.in_hot_file,
                "gitignored": f.gitignored,
            }
            for f in result.findings
        ],
    }, indent=2, ensure_ascii=False)
