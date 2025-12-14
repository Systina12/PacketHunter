# src/packethunter/workflow/scan_result.py
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional

from rich.panel import Panel

from packethunter.analyzers.scanner import detect_scanners
from packethunter.features.http_probe import HttpRequest
from packethunter.tshark2python.tshark_runner import run_tshark
from packethunter.ui.console import Hit, console, info, print_hit


@dataclass
class ScanResult:
    request: Optional[HttpRequest]
    server_ip: str
    status: str
    body: str = ""


def _clip_text(s: str, limit: int = 4000) -> str:
    if not s:
        return ""
    s = s.replace("\r", "")
    if len(s) <= limit:
        return s
    return s[:limit] + "…(truncated)"


def _analyze_http_scan_streaming(pcap: str, scanner_ip: str) -> List[ScanResult]:
    """
    根据扫描器 IP 复刻 HTTP 请求与响应。
    - 非 200：仅 info 输出 IP/域名/状态码
    - 200：收集 body，并以富文本展示完整内容
    """
    info(f"[scan_result] Streaming HTTP scan reconstruction for scanner_ip={scanner_ip}")

    pending_reqs: Dict[str, Deque[HttpRequest]] = defaultdict(deque)
    last_result_idx: Dict[str, int] = {}
    results: List[ScanResult] = []

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

        # 1) request：扫描器 -> server
        if req_method or req_uri:
            if ip_src != scanner_ip:
                continue

            req = HttpRequest(
                src_ip=scanner_ip,
                dst_ip=ip_dst or "",
                method=(req_method or "GET").upper(),
                host=req_host or "",
                uri=req_uri or "",
                user_agent=req_ua or "",
            )
            pending_reqs[stream].append(req)

            print_hit(
                Hit(
                    scanner="scan_result",
                    src_ip=scanner_ip,
                    detail=f"REQ {req.method} {req.url()} ua={req.user_agent}",
                    severity="bad",
                )
            )
            continue

        # 2) response header：server -> scanner，带状态码
        if resp_code:
            if ip_dst != scanner_ip:
                continue

            req = pending_reqs[stream].popleft() if pending_reqs[stream] else None
            server_ip = ip_src or ""

            res = ScanResult(
                request=req,
                server_ip=server_ip,
                status=resp_code,
                body="",
            )
            results.append(res)
            last_result_idx[stream] = len(results) - 1
            continue

        # 3) body chunk：http.file_data（可能出现在后续包）
        if file_data:
            idx = last_result_idx.get(stream)
            if idx is None:
                continue
            if results[idx].status != "200":
                continue

            current = results[idx].body
            combined = current + file_data
            results[idx].body = _clip_text(combined, limit=4000)

    return results


def _print_summary(scanner_ip: str, scanner_name: str, results: List[ScanResult]) -> None:
    if not results:
        console.print(f"[bold red]No HTTP scan results reconstructed for {scanner_ip}.[/]")
        return

    for r in results:
        host = r.request.host if r.request else r.server_ip
        url = r.request.url() if r.request else f"http://{host}"

        if r.status != "200":
            info(f"{scanner_name}({scanner_ip}) -> {host} returned HTTP {r.status}")
            continue

        panel_title = f"{scanner_name} {scanner_ip} -> {host} [HTTP {r.status}]"
        panel = Panel(
            r.body or "(empty body)",
            title=panel_title,
            subtitle=url,
            expand=False,
        )
        console.print(panel)


def main(pcap: str) -> None:
    info(f"Analyzing pcap (scan_result): {pcap}")

    detection = detect_scanners(pcap, emit=False)
    if not detection.results:
        console.print("[bold red]No scanner candidates detected. Nothing to reconstruct.[/]")
        return

    for result in detection.results:
        results = _analyze_http_scan_streaming(pcap, result.src_ip)
        _print_summary(result.src_ip, result.scanner, results)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", help="Path to pcap/pcapng")
    args = parser.parse_args()
    main(args.pcap)
