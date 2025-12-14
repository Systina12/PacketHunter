# src/packethunter/features/http_probe.py
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Tuple

from packethunter.data.signature import UA_SIGNATURES
from packethunter.tshark2python.tshark_runner import run_tshark
from packethunter.ui.console import Hit, info, print_hit


@dataclass
class HttpFeatures:
    # src_ip -> list of ua strings
    user_agents: Dict[str, List[str]]
    # src_ip -> uri count
    uri_count: Dict[str, int]
    # (src_ip, scanner) -> hit count
    ua_hits: Dict[Tuple[str, str], int]
    # src_ip -> captured requests
    requests: Dict[str, List["HttpRequest"]]


@dataclass
class HttpRequest:
    """Structured record of a single HTTP request."""

    src_ip: str
    dst_ip: str
    method: str
    host: str
    uri: str
    user_agent: str

    def url(self) -> str:
        host_or_ip = self.host or self.dst_ip
        return f"http://{host_or_ip}{self.uri}" if host_or_ip else self.uri


def extract_http_features(pcap: str) -> HttpFeatures:
    """
    提取 HTTP 请求的 UA/URI，并且发现命中时即时输出（红色）
    """

    info("Starting HTTP UA inspection (streaming)")

    user_agents: Dict[str, List[str]] = defaultdict(list)
    uri_count: Dict[str, int] = defaultdict(int)
    ua_hits: Dict[Tuple[str, str], int] = defaultdict(int)
    requests: Dict[str, List[HttpRequest]] = defaultdict(list)

    for row in run_tshark(
        pcap,
        "http.request",
        ["ip.src", "ip.dst", "http.request.method", "http.user_agent", "http.request.uri", "http.host"],
    ):
        # 容错：字段可能缺失
        parts = row.fields + ["", "", "", "", "", ""]
        src, dst, method, ua, uri, host = parts[:6]

        if not src:
            continue

        uri_count[src] += 1

        request = HttpRequest(
            src_ip=src,
            dst_ip=dst or "",
            method=(method or "GET").upper(),
            host=host or "",
            uri=uri or "",
            user_agent=ua or "",
        )
        requests[src].append(request)

        ua_l = request.user_agent.lower()
        if ua_l:
            user_agents[src].append(ua_l)

            for scanner, sigs in UA_SIGNATURES.items():
                if any(sig in ua_l for sig in sigs):
                    ua_hits[(src, scanner)] += 1

                    print_hit(
                        Hit(
                            scanner=scanner,
                            src_ip=src,
                            detail=f"HTTP UA hit: {request.user_agent}  uri={request.uri}",
                            severity="bad",
                        )
                    )

    return HttpFeatures(
        user_agents=dict(user_agents),
        uri_count=dict(uri_count),
        ua_hits=dict(ua_hits),
        requests=dict(requests),
    )
