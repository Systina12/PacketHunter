# src/packethunter/features/syn_scan.py
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set

from packethunter.data.signature import SCAN_THRESHOLDS, TOPK_DEFAULT
from packethunter.tshark2python.tshark_runner import run_tshark
from packethunter.ui.console import info, ok, warn


@dataclass
class SynStats:
    syn_count: int = 0
    ports: Set[str] = field(default_factory=set)
    hosts: Set[str] = field(default_factory=set)
    samples: List[str] = field(default_factory=list)


@dataclass
class SynScanFeatures:
    per_src: Dict[str, SynStats] = field(default_factory=dict)

    def candidate_sources(self) -> List[str]:
        candidates: List[str] = []
        for src, stats in self.per_src.items():
            if (
                stats.syn_count >= SCAN_THRESHOLDS["min_syn"]
                and len(stats.ports) >= SCAN_THRESHOLDS["min_ports"]
                and len(stats.hosts) >= SCAN_THRESHOLDS["min_hosts"]
            ):
                candidates.append(src)
        return sorted(candidates)


def extract_syn_scan_features(pcap: str) -> SynScanFeatures:
    """
    Collect SYN statistics for every source IP. The data is retained for later
    scoring instead of being printed and forgotten.
    """

    info("Starting SYN scan detection (streaming)")

    per_src: Dict[str, SynStats] = defaultdict(SynStats)
    fields = ["ip.src", "ip.dst", "tcp.dstport"]

    for row in run_tshark(pcap, "tcp.flags.syn==1 && tcp.flags.ack==0", fields):
        parts = row.fields + [""] * (len(fields) - len(row.fields))
        src, dst, dport = parts[:3]
        if not src:
            continue

        stats = per_src[src]
        stats.syn_count += 1
        if dport:
            stats.ports.add(dport)
        if dst:
            stats.hosts.add(dst)
        if len(stats.samples) < 5 and dst and dport:
            stats.samples.append(f"{dst}:{dport}")

    if not per_src:
        warn("No SYN packets found (filter matched 0)")
        return SynScanFeatures(per_src={})

    top = sorted(
        per_src.items(),
        key=lambda kv: (kv[1].syn_count, len(kv[1].ports), len(kv[1].hosts)),
        reverse=True,
    )[:TOPK_DEFAULT]

    ok("Top SYN sources:")
    for src, stats in top:
        ok(
            f"{src}: SYN={stats.syn_count} ports={len(stats.ports)} hosts={len(stats.hosts)}"
        )

    return SynScanFeatures(per_src=dict(per_src))


def find_scan_candidates(syn_features: SynScanFeatures) -> List[str]:
    """
    Backwards compatible wrapper returning candidate scanner IPs.
    """

    return syn_features.candidate_sources()
