"""envleak — find exposed credentials before someone else does.

Runs entirely on your machine. Nothing is uploaded, ever.
"""

import argparse
import sys

from . import __version__
from .report import compute_score, render_json, render_markdown, render_terminal
from .scanner import scan


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="envleak",
        description="Escanea credenciales expuestas. 100%% local, no sube nada.",
    )
    p.add_argument("path", nargs="?", default=".", help="directorio a escanear (default: .)")
    p.add_argument("--json", action="store_true", help="salida JSON")
    p.add_argument("--markdown", "--md", action="store_true", dest="markdown",
                   help="scorecard en markdown, listo para pegar")
    p.add_argument("--no-color", action="store_true", help="sin colores ANSI")
    p.add_argument("--fail-on", choices=["none", "medium", "high", "critical"],
                   default="high",
                   help="código de salida 1 si hay hallazgos de este nivel o peor "
                        "(default: high). Útil en CI.")
    p.add_argument("--max-files", type=int, default=20000)
    p.add_argument("--version", action="version", version=f"envleak {__version__}")
    args = p.parse_args(argv)

    try:
        result = scan(args.path, max_files=args.max_files)
    except FileNotFoundError:
        print(f"envleak: no existe la ruta {args.path}", file=sys.stderr)
        return 2
    except PermissionError:
        print(f"envleak: sin permiso para leer {args.path}", file=sys.stderr)
        return 2

    if args.json:
        print(render_json(result))
    elif args.markdown:
        print(render_markdown(result))
    else:
        color = not args.no_color and sys.stdout.isatty()
        print(render_terminal(result, color=color))

    if args.fail_on == "none":
        return 0
    order = {"medium": 0, "high": 1, "critical": 2}
    threshold = order[args.fail_on]
    worst = max((order[f.severity] for f in result.findings), default=-1)
    return 1 if worst >= threshold else 0


def _entry() -> int:
    """Console entry point that survives `| head` without a traceback."""
    try:
        return main()
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(_entry())
