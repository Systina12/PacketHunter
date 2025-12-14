# src/packethunter/workflow/detect_scanner.py
from __future__ import annotations

import argparse
from pathlib import Path

from packethunter.analyzers.scanner import detect_scanners, emit_result_live
from packethunter.ui.console import headline, info, ok, warn


def main(pcap_path: str) -> int:
    pcap = Path(pcap_path)
    headline("PacketHunter - Detect Scanner")
    info(f"Analyzing pcap: {pcap}")

    if not pcap.exists():
        warn(f"PCAP not found: {pcap}")
        return 2

    detection = detect_scanners(str(pcap), emit=False)

    if not detection.results:
        ok("Analysis finished")
        return 0

    headline("Candidates & Classification")
    for result in detection.results:
        emit_result_live(result)
        for ev in result.evidence:
            info(f"{result.src_ip}: {ev}")

    ok("Analysis finished")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "pcap",
        help="Path to pcap/pcapng",
    )
    args = parser.parse_args()
    raise SystemExit(main(args.pcap))
