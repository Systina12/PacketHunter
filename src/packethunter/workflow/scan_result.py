# src/packethunter/workflow/scan_result.py
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque, Dict, List

from rich.table import Table

from packethunter.analyzers.scanner import detect_scanners
from packethunter.features.http_probe import extract_http_features
from packethunter.features.syn_scan import extract_syn_scan_features
from packethunter.tshark2python.tshark_runner import run_tshark
from packethunter.ui.console import console, headline, info, warn


@dataclass
class HttpExchange:
    url: str
    status: str
    server_ip: str
    user_agent: str
    body: str = ""


def _trim_body(body: str, limit: int = 4000) -> str:
    if len(body) <= limit:
        return body
    return body[:limit] + "\n...[truncated]"


def _reconstruct_http(pcap: str, scanner_ip: str) -> List[HttpExchange]:
    display_filter = f"ip.addr=={scanner_ip} && http"
    fields = [
        "tcp.stream",
        "ip.src",
        "ip.dst",
        "http.request.method",
        "http.host",
        "http.request.uri",
        "http.user_agent",
        "http.response.code",
        "http.file_data",
    ]

    pending: Dict[str, Deque[dict]] = defaultdict(deque)
    last_response: Dict[str, int] = {}
    exchanges: List[HttpExchange] = []

    for row in run_tshark(pcap, display_filter, fields):
        parts = row.fields + [""] * (len(fields) - len(row.fields))
        (
            stream,
            ip_src,
            ip_dst,
            req_method,
            req_host,
            req_uri,
            req_ua,
            resp_code,
            file_data,
        ) = parts[:9]

        if not stream:
            continue

        if req_method or req_uri:
            if ip_src != scanner_ip:
                continue
            pending[stream].append(
                {
                    "host": req_host or "",
                    "uri": req_uri or "",
                    "ua": req_ua or "",
                }
            )
            continue

        if resp_code:
            if ip_dst != scanner_ip:
                continue
            req = pending[stream].popleft() if pending[stream] else {"host": "", "uri": "", "ua": ""}
            host = req["host"] or ip_src or ""
            url = f"http://{host}{req['uri']}"
            exchange = HttpExchange(
                url=url,
                status=resp_code,
                server_ip=ip_src or "",
                user_agent=req["ua"],
                body="",
            )
            exchanges.append(exchange)
            last_response[stream] = len(exchanges) - 1
            continue

        if file_data:
            idx = last_response.get(stream)
            if idx is None:
                continue
            if exchanges[idx].status != "200":
                continue
            exchanges[idx].body = _trim_body(exchanges[idx].body + file_data)

    return exchanges


def _render_exchanges(scanner_ip: str, scanner_name: str, exchanges: List[HttpExchange]) -> None:
    headline(f"扫描结果 {scanner_ip} ({scanner_name})")
    if not exchanges:
        warn("No HTTP conversations reconstructed for this scanner")
        return

    table = Table(title="HTTP Responses", show_lines=True)
    table.add_column("Status", justify="right")
    table.add_column("URL", overflow="fold")
    table.add_column("User-Agent", overflow="fold")
    table.add_column("Body (200 only)", overflow="fold")

    for ex in exchanges:
        if ex.status != "200":
            info(f"{ex.status} {ex.url}")
            table.add_row(ex.status, ex.url, ex.user_agent, "")
            continue

        info(f"{ex.status} {ex.url} -> full response captured")
        body = ex.body or "(empty body)"
        table.add_row(ex.status, ex.url, ex.user_agent, body)

    console.print(table)


def main(pcap_path: str) -> int:
    pcap = Path(pcap_path)
    headline("PacketHunter - Scan Result")
    info(f"Analyzing pcap: {pcap}")

    if not pcap.exists():
        warn(f"PCAP not found: {pcap}")
        return 2

    syn_features = extract_syn_scan_features(str(pcap))
    http_features = extract_http_features(str(pcap))
    scanners = detect_scanners(syn_features, http_features)

    if not scanners:
        warn("No scanners detected; nothing to reconstruct.")
        return 0

    for scanner in scanners:
        exchanges = _reconstruct_http(str(pcap), scanner.src_ip)
        _render_exchanges(scanner.src_ip, scanner.scanner, exchanges)

    return 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", help="Path to pcap/pcapng")
    args = parser.parse_args()
    raise SystemExit(main(args.pcap))
