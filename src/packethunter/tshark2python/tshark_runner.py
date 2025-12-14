# src/packethunter/tshark2python/tshark_runner.py
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional


@dataclass(frozen=True)
class TsharkRow:
    fields: list[str]


def run_tshark(
    pcap: str,
    display_filter: str,
    fields: List[str],
    *,
    tshark_path: str = "tshark",
) -> Iterator[TsharkRow]:

    cmd = [tshark_path, "-r", pcap, "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )

    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip("\n")
        # tshark fields 可能出现空字段，split 后长度会变化，这里不强行校验长度
        yield TsharkRow(fields=line.split("\t"))

    # 读完后检查退出码
    proc.wait()
    if proc.returncode not in (0, None):
        err = ""
        if proc.stderr:
            err = proc.stderr.read()
        raise RuntimeError(f"tshark failed (code={proc.returncode}). stderr:\n{err}")
