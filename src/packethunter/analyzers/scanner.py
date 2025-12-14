# src/packethunter/analyzers/scanner.py
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List

from packethunter.data.signature import SCAN_THRESHOLDS
from packethunter.features.http_probe import HttpFeatures, UserAgentHit
from packethunter.features.syn_scan import SynScanFeatures
from packethunter.ui.console import Hit, info, print_hit, warn


@dataclass
class ScannerResult:
    src_ip: str
    scanner: str
    score: int
    evidence: List[str]


def _score_user_agents(src_ip: str, ua_hits: List[UserAgentHit]) -> Dict[str, int]:
    scores: Dict[str, int] = defaultdict(int)
    for hit in ua_hits:
        if hit.src_ip != src_ip:
            continue
        scores[hit.scanner] += 15
    return scores


def _score_syn_behavior(src_ip: str, syn_features: SynScanFeatures) -> tuple[Dict[str, int], List[str]]:
    scores: Dict[str, int] = defaultdict(int)
    evidence: List[str] = []

    stats = syn_features.per_src.get(src_ip)
    if not stats:
        return scores, evidence

    ratio = stats.syn_count / max(len(stats.ports), 1)
    evidence.append(
        f"SYN packets={stats.syn_count}, unique_ports={len(stats.ports)}, hosts={len(stats.hosts)}, ratio={ratio:.2f}"
    )

    has_threshold = (
        stats.syn_count >= SCAN_THRESHOLDS["min_syn"]
        and len(stats.ports) >= SCAN_THRESHOLDS["min_ports"]
    )
    if has_threshold and ratio > 0.9:
        scores["masscan"] += 8
        evidence.append("High SYN/port ratio -> masscan-likely")
    elif stats.syn_count:
        scores["nmap"] += 5
        evidence.append("Mixed SYN footprint -> nmap-likely")

    return scores, evidence


def score_scanner(src_ip: str, syn_features: SynScanFeatures, http_features: HttpFeatures) -> ScannerResult:
    evidence: List[str] = []
    scores: Dict[str, int] = defaultdict(int)

    ua_scores = _score_user_agents(src_ip, http_features.ua_hits)
    if ua_scores:
        for scanner, val in ua_scores.items():
            scores[scanner] += val
            evidence.append(f"UA signature matched {scanner} x{val // 15}")

    syn_scores, syn_evidence = _score_syn_behavior(src_ip, syn_features)
    for scanner, val in syn_scores.items():
        scores[scanner] += val
    evidence.extend(syn_evidence)

    if not scores:
        warn(f"No strong scanner fingerprint for {src_ip}. Marking as unknown.")
        return ScannerResult(src_ip=src_ip, scanner="unknown", score=0, evidence=evidence)

    scanner = max(scores, key=scores.get)
    return ScannerResult(src_ip=src_ip, scanner=scanner, score=scores[scanner], evidence=evidence)


def detect_scanners(syn_features: SynScanFeatures, http_features: HttpFeatures) -> List[ScannerResult]:
    candidates = set(syn_features.per_src.keys()) | set(http_features.request_count.keys())
    candidates |= {hit.src_ip for hit in http_features.ua_hits}

    if not candidates:
        warn("No scanner candidates detected in capture")
        return []

    results: List[ScannerResult] = []
    info(f"Scoring {len(candidates)} candidate scanner IPs")
    for src in sorted(candidates):
        result = score_scanner(src, syn_features, http_features)
        results.append(result)
        emit_result_live(result)

    return results


def emit_result_live(result: ScannerResult) -> None:
    print_hit(
        Hit(
            scanner=result.scanner,
            src_ip=result.src_ip,
            detail=f"score={result.score}",
            severity="bad" if result.scanner != "unknown" else "warn",
        )
    )
