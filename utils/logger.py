#!/usr/bin/env python3
"""Colored logging for claudebbp — uses rich when available, ANSI fallback."""
import sys

try:
    from rich.console import Console
    from rich.theme import Theme

    _theme = Theme({
        "info":    "bold cyan",
        "success": "bold green",
        "warn":    "bold yellow",
        "error":   "bold red",
        "finding": "bold magenta",
        "section": "bold blue",
        "dim":     "dim white",
    })
    _console = Console(theme=_theme, highlight=False)

    def info(msg: str)    -> None: _console.print(f"[info]  >[/info] {msg}")
    def success(msg: str) -> None: _console.print(f"[success][+][/success] {msg}")
    def warn(msg: str)    -> None: _console.print(f"[warn][!][/warn] {msg}")
    def error(msg: str)   -> None: _console.print(f"[error][-][/error] {msg}", file=sys.stderr)
    def finding(msg: str) -> None: _console.print(f"[finding][FINDING][/finding] {msg}")
    def dim(msg: str)     -> None: _console.print(f"[dim]{msg}[/dim]")

    def section(title: str) -> None:
        _console.rule(f"[section]{title}[/section]")

    def banner(text: str) -> None:
        from rich.panel import Panel
        _console.print(Panel(text, style="bold blue"))

    def table(headers: list, rows: list) -> None:
        from rich.table import Table
        t = Table(show_header=True, header_style="bold cyan")
        for h in headers:
            t.add_column(h)
        for row in rows:
            t.add_row(*[str(c) for c in row])
        _console.print(t)

except ImportError:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"
    M = "\033[95m"; B = "\033[94m"; D = "\033[2m";  X = "\033[0m"

    def info(msg: str)    -> None: print(f"{C}  >{X} {msg}")
    def success(msg: str) -> None: print(f"{G}[+]{X} {msg}")
    def warn(msg: str)    -> None: print(f"{Y}[!]{X} {msg}")
    def error(msg: str)   -> None: print(f"{R}[-]{X} {msg}", file=sys.stderr)
    def finding(msg: str) -> None: print(f"{M}[FINDING]{X} {msg}")
    def dim(msg: str)     -> None: print(f"{D}{msg}{X}")
    def section(title: str) -> None: print(f"\n{B}{'='*60}{X}\n{B}{title}{X}\n{B}{'='*60}{X}")
    def banner(text: str)   -> None: section(text)
    def table(headers: list, rows: list) -> None:
        widths = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
                  for i, h in enumerate(headers)]
        fmt = "  ".join(f"{{:<{w}}}" for w in widths)
        print(fmt.format(*headers))
        print("  ".join("-" * w for w in widths))
        for row in rows:
            print(fmt.format(*[str(c) for c in row]))
