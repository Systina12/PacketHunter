# src/packethunter/ui/console.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

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

console = Console(theme=THEME)


def info(msg: str) -> None:
    console.print(f"[*] {msg}", style="info")


def ok(msg: str) -> None:
    console.print(f"[+] {msg}", style="ok")


def warn(msg: str) -> None:
    console.print(f"[!] {msg}", style="warn")


def bad(msg: str) -> None:
    console.print(f"[x] {msg}", style="bad")


def headline(msg: str) -> None:
    console.rule(f"[title]{msg}[/title]")


@dataclass(frozen=True)
class Hit:
    scanner: str
    src_ip: str
    detail: str
    severity: str = "bad"  # bad / warn / ok / info


def print_hit(hit: Hit) -> None:
    style = hit.severity if hit.severity in {"bad", "warn", "ok", "info"} else "bad"
    console.print(f"[{hit.scanner}] {hit.src_ip} -> {hit.detail}", style=style)
