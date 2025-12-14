# src/packethunter/analyzers/scanner.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple
from collections import defaultdict

from packethunter.features.http_probe import HttpFeatures
from packethunter.features.syn_scan import SynScanFeatures
from packethunter.ui.console import Hit, print_hit, warn


@dataclass
class ScannerResult:
    src_ip: str
    scanner: str
    score: int
    evidence: List[str]




def score_scanner(
    src_ip: str,
    syn_features: SynScanFeatures,
    http_features: HttpFeatures,
) -> ScannerResult:
    """
    综合 SYN 行为 + UA 命中进行打分判定
    """
    score: Dict[str, int] = defaultdict(int)
    evidence: List[str] = []

    # 1) UA 命中：强证据
    for (ip, scanner), cnt in http_features.ua_hits.items():
        if ip != src_ip:
            continue
        score[scanner] += cnt * 10
        evidence.append(f"UA signature matched {scanner} x{cnt}")

    # 2) SYN 行为：弱证据，用于区分 masscan/nmap 倾向
    s = syn_features.per_src.get(src_ip)
    if s:
        syn = s.syn
        ports = max(len(s.ports), 1)
        ratio = syn / ports
        evidence.append(f"SYN packets={syn}, unique_ports={len(s.ports)}, ratio={ratio:.2f}")

        # 如果几乎全是 SYN 且没有 HTTP 痕迹，更像 masscan
        has_http = src_ip in http_features.uri_count
        if ratio > 0.9 and not has_http:
            score["masscan"] += 8
            evidence.append("High SYN/port ratio with no HTTP -> masscan likely")
        else:
            score["nmap"] += 3
            evidence.append("Not purely SYN-only -> nmap-like likely")

    if not score:
        warn(f"No strong scanner fingerprint for {src_ip}. Marking as unknown.")
        return ScannerResult(src_ip=src_ip, scanner="unknown", score=0, evidence=evidence)

    scanner = max(score, key=score.get)
    return ScannerResult(src_ip=src_ip, scanner=scanner, score=score[scanner], evidence=evidence)


def emit_result_live(result: ScannerResult) -> None:
    # 结果也用红色打一行，别让用户不知道发生什么
    print_hit(Hit(scanner=result.scanner, src_ip=result.src_ip, detail=f"score={result.score}", severity="bad"))
