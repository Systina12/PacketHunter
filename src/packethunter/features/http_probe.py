# src/packethunter/features/http_probe.py
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from packethunter.data.signature import UA_SIGNATURES
from packethunter.tshark2python.tshark_runner import run_tshark
from packethunter.ui.console import Hit, info, print_hit, warn


@dataclass(frozen=True)
class HttpRequest:
    src_ip: str
    dst_ip: str
    method: str
    host: str
    uri: str
    user_agent: str
    stream: str

    @property
    def url(self) -> str:
        host = self.host or self.dst_ip or ""
        return f"http://{host}{self.uri}"


@dataclass(frozen=True)
class UserAgentHit:
    src_ip: str
    scanner: str
    user_agent: str
    uri: str


@dataclass
class HttpFeatures:
    requests: List[HttpRequest] = field(default_factory=list)
    ua_hits: List[UserAgentHit] = field(default_factory=list)
    request_count: Dict[str, int] = field(default_factory=dict)
    hit_count: Dict[Tuple[str, str], int] = field(default_factory=dict)

    def sources(self) -> List[str]:
        all_ips = set(self.request_count.keys()) | {hit.src_ip for hit in self.ua_hits}
        return sorted(all_ips)


def _record_hit(hit: UserAgentHit) -> None:
    print_hit(
        Hit(
            scanner=hit.scanner,
            src_ip=hit.src_ip,
            detail=f"HTTP UA hit: {hit.user_agent} uri={hit.uri}",
            severity="bad",
        )
    )


def extract_http_features(pcap: str) -> HttpFeatures:
    """
    Stream HTTP requests to capture user-agents and URIs.

    The extractor keeps every request for later workflows while emitting
    real-time hits for any user-agent that matches known scanner signatures.
    """

    info("Starting HTTP inspection (streaming)")

    requests: List[HttpRequest] = []
    ua_hits: List[UserAgentHit] = []
    request_count: Dict[str, int] = defaultdict(int)
    hit_count: Dict[Tuple[str, str], int] = defaultdict(int)

    fields = [
        "ip.src",
        "ip.dst",
        "http.request.method",
        "http.host",
        "http.request.uri",
        "http.user_agent",
        "tcp.stream",
    ]

    for row in run_tshark(pcap, "http.request", fields):
        parts = row.fields + [""] * (len(fields) - len(row.fields))
        src, dst, method, host, uri, ua, stream = parts[:7]

        if not src:
            continue

        method = method or "GET"
        request = HttpRequest(
            src_ip=src,
            dst_ip=dst or "",
            method=method,
            host=host or "",
            uri=uri or "",
            user_agent=ua or "",
            stream=stream or "",
        )
        requests.append(request)
        request_count[src] += 1

        ua_l = request.user_agent.casefold()
        if not ua_l:
            continue

        for scanner, sigs in UA_SIGNATURES.items():
            if any(sig.casefold() in ua_l for sig in sigs):
                hit = UserAgentHit(
                    src_ip=src,
                    scanner=scanner,
                    user_agent=request.user_agent,
                    uri=request.uri,
                )
                ua_hits.append(hit)
                hit_count[(src, scanner)] += 1
                _record_hit(hit)

    if not requests:
        warn("No HTTP requests observed in capture")

    return HttpFeatures(
        requests=requests,
        ua_hits=ua_hits,
        request_count=dict(request_count),
        hit_count=dict(hit_count),
    )
