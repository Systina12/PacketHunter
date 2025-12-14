# src/packethunter/features/syn_scan.py
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Set, Tuple, List

from packethunter.data.signature import SCAN_THRESHOLDS, TOPK_DEFAULT
from packethunter.tshark2python.tshark_runner import run_tshark
from packethunter.ui.console import info, ok, warn


@dataclass
class SynStats:
    syn: int
    ports: Set[str]
    hosts: Set[str]


@dataclass
class SynScanFeatures:
    # src_ip -> SynStats
    per_src: Dict[str, SynStats]


def extract_syn_scan_features(pcap: str) -> SynScanFeatures:
    """
    采集 SYN 包统计，用于识别扫描源。
    """
    info("Starting SYN scan detection (streaming)")

    per_src: Dict[str, SynStats] = defaultdict(lambda: SynStats(syn=0, ports=set(), hosts=set()))

    for row in run_tshark(
        pcap,
        "tcp.flags.syn==1 && tcp.flags.ack==0",
        ["ip.src", "ip.dst", "tcp.dstport"],
    ):
        parts = row.fields + ["", "", ""]
        src, dst, dport = parts[0], parts[1], parts[2]
        if not src:
            continue

        s = per_src[src]
        s.syn += 1
        if dport:
            s.ports.add(dport)
        if dst:
            s.hosts.add(dst)

    # 给用户一点“别盯空白”的反馈：打印 top talkers
    if not per_src:
        warn("No SYN packets found (filter matched 0).")
        return SynScanFeatures(per_src={})

    top = sorted(
        per_src.items(),
        key=lambda kv: (kv[1].syn, len(kv[1].ports), len(kv[1].hosts)),
        reverse=True
    )[:TOPK_DEFAULT]

    ok("Top SYN sources:")
    for src, s in top:
        ok(f"{src}: SYN={s.syn} ports={len(s.ports)} hosts={len(s.hosts)}")

    return SynScanFeatures(per_src=dict(per_src))


def find_scan_candidates(syn_features: SynScanFeatures) -> List[str]:
    """
    根据阈值筛出可疑扫描源 IP
    """
    candidates: List[str] = []
    for src, s in syn_features.per_src.items():
        if (
            s.syn >= SCAN_THRESHOLDS["min_syn"]
            and len(s.ports) >= SCAN_THRESHOLDS["min_ports"]
            and len(s.hosts) >= SCAN_THRESHOLDS["min_hosts"]
        ):
            candidates.append(src)
    return sorted(candidates)
