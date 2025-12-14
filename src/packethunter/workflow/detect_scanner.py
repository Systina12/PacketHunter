# src/packethunter/workflow/detect_scanner.py
from __future__ import annotations

import argparse
from pathlib import Path

from packethunter.analyzers.scanner import detect_scanners
from packethunter.features.http_probe import extract_http_features
from packethunter.features.syn_scan import extract_syn_scan_features
from packethunter.ui.console import headline, info, ok, warn


def _print_summary(results) -> None:
    if not results:
        return

    headline("扫描总结")
    for r in results:
        ok(f"{r.src_ip} 使用 {r.scanner} (score={r.score})")
        for ev in r.evidence:
            info(f"{r.src_ip}: {ev}")


def main(pcap_path: str) -> int:
    pcap = Path(pcap_path)
    headline("PacketHunter - Detect Scanner")
    info(f"Analyzing pcap: {pcap}")

    if not pcap.exists():
        warn(f"PCAP not found: {pcap}")
        return 2

    syn_features = extract_syn_scan_features(str(pcap))
    http_features = extract_http_features(str(pcap))

    results = detect_scanners(syn_features, http_features)
    if not results:
        warn("No scanner candidates met thresholds or signatures.")
        ok("Analysis finished")
        return 0

    _print_summary(results)
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
