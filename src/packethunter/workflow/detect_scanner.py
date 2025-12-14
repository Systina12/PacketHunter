# src/packethunter/workflow/detect_scanner.py
from __future__ import annotations

import argparse
from pathlib import Path

from packethunter.ui.console import headline, info, ok, warn
from packethunter.features.syn_scan import extract_syn_scan_features, find_scan_candidates
from packethunter.features.http_probe import extract_http_features
from packethunter.analyzers.scanner import score_scanner, emit_result_live


def main(pcap_path: str) -> int:
    pcap = Path(pcap_path)
    headline("PacketHunter - Detect Scanner")
    info(f"Analyzing pcap: {pcap}")

    if not pcap.exists():
        warn(f"PCAP not found: {pcap}")
        return 2

    syn_features = extract_syn_scan_features(str(pcap))
    http_features = extract_http_features(str(pcap))

    candidates = find_scan_candidates(syn_features)

    if not candidates:
        warn("No scan candidates met thresholds.")
        ok("Analysis finished")
        return 0

    headline("Candidates & Classification")
    for src in candidates:
        result = score_scanner(src, syn_features, http_features)
        emit_result_live(result)
        for ev in result.evidence:
            info(f"{src}: {ev}")

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
