# src/packethunter/ui/console.py
from __future__ import annotations

from dataclasses import dataclass
from typing import IO, Optional

from rich.console import Console
from rich.theme import Theme

THEME = Theme(
    {
        "info": "cyan",
        "ok": "green",
        "warn": "yellow",
        "bad": "bold red",
        "dim": "dim",
        "title": "bold white",
    }
)

console = Console(theme=THEME, legacy_windows=False, encoding="utf-8", errors="replace")
_log_file: Optional[IO[str]] = None


def set_log_file(path: str) -> None:
    """Duplicate console output to a UTF-8 text file."""

    global _log_file
    if _log_file and not _log_file.closed:
        _log_file.close()
    _log_file = open(path, "w", encoding="utf-8", errors="replace")


def _write(msg: str) -> None:
    if _log_file:
        _log_file.write(msg + "\n")
        _log_file.flush()


def info(msg: str) -> None:
    console.print(f"[*] {msg}", style="info")
    _write(f"[*] {msg}")


def ok(msg: str) -> None:
    console.print(f"[+] {msg}", style="ok")
    _write(f"[+] {msg}")


def warn(msg: str) -> None:
    console.print(f"[!] {msg}", style="warn")
    _write(f"[!] {msg}")


def bad(msg: str) -> None:
    console.print(f"[x] {msg}", style="bad")
    _write(f"[x] {msg}")


def headline(msg: str) -> None:
    console.rule(f"[title]{msg}[/title]")
    _write(msg)


@dataclass(frozen=True)
class Hit:
    scanner: str
    src_ip: str
    detail: str
    severity: str = "bad"  # bad / warn / ok / info


def print_hit(hit: Hit) -> None:
    style = hit.severity if hit.severity in {"bad", "warn", "ok", "info"} else "bad"
    console.print(f"[{hit.scanner}] {hit.src_ip} -> {hit.detail}", style=style)
    _write(f"[{hit.scanner}] {hit.src_ip} -> {hit.detail}")
