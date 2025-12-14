# src/packethunter/workflow/scan_result.py
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Tuple

from rich.table import Table

from packethunter.analyzers.scanner import detect_scanners
from packethunter.tshark2python.tshark_runner import run_tshark
from packethunter.ui.console import Hit, console, info, print_hit


@dataclass
class RequestInfo:
    method: str
    host: str
    uri: str
    ua: str
    dst_ip: str

    def url(self) -> str:
        host = self.host or self.dst_ip or ""
        # 题目环境大多是 http；你需要 https 的话后面再加判断
        return f"http://{host}{self.uri}"


@dataclass
class ScanResult:
    scanner_ip: str
    server_ip: str
    url: str
    status: str
    body_preview: str = ""


def _clip_text(s: str, limit: int = 800) -> str:
    if not s:
        return ""
    s = s.replace("\r", "")
    if len(s) <= limit:
        return s
    return s[:limit] + "…(truncated)"


def _analyze_http_scan_streaming(pcap: str, scanner_ip: str) -> List[ScanResult]:
    """
    复刻“扫描结果”：把扫描器发出的请求与返回包关联。
    规则：
      - 非 200：只输出 url + status
      - 200：输出 url + status + 返回内容（body 片段）
    关联策略：
      - 使用 tcp.stream
      - 对同一 stream 里多次 request/response，用队列一一配对（支持 keep-alive）
      - body 用 http.file_data 片段（出现在哪个包就拼到最近一次 response 上）
    """
    info(f"[scan_result] Streaming HTTP scan reconstruction for scanner_ip={scanner_ip}")

    # stream -> pending requests queue
    pending_reqs: Dict[str, Deque[RequestInfo]] = defaultdict(deque)
    # stream -> last emitted result index (so we can append file_data)
    last_result_idx: Dict[str, int] = {}
    results: List[ScanResult] = []

    # 一次 tshark 流式跑完：request / response / file_data 都在 http dissector 下
    # 用 ip.addr==scanner_ip 限定只看扫描器相关会话
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
            # 只认 scanner_ip 发出的 request
            if ip_src != scanner_ip:
                continue

            req = RequestInfo(
                method=req_method or "GET",
                host=req_host or "",
                uri=req_uri or "",
                ua=req_ua or "",
                dst_ip=ip_dst or "",
            )
            pending_reqs[stream].append(req)

            # 你要的“立刻输出”：发现扫描请求马上红色吐一条
            print_hit(
                Hit(
                    scanner="scan_result",
                    src_ip=scanner_ip,
                    detail=f"REQ {req.method} {req.url()}  ua={req.ua}",
                    severity="bad",
                )
            )
            continue

        # 2) response header：server -> scanner，带状态码
        if resp_code:
            # 只认发回给 scanner 的 response
            if ip_dst != scanner_ip:
                continue

            # 配对：同一 tcp.stream 弹出最早的 request
            req = pending_reqs[stream].popleft() if pending_reqs[stream] else None
            url = req.url() if req else "(unknown-url)"
            server_ip = ip_src or ""

            res = ScanResult(
                scanner_ip=scanner_ip,
                server_ip=server_ip,
                url=url,
                status=resp_code,
                body_preview="",
            )
            results.append(res)
            last_result_idx[stream] = len(results) - 1

            # 立刻输出：状态码不是 200 就先吐 URL + code
            if resp_code != "200":
                console.print(f"[bold yellow]{resp_code}[/] {url}")
            else:
                console.print(f"[bold green]{resp_code}[/] {url}  [dim](collecting body…)[/dim]")
            continue

        # 3) body chunk：http.file_data（可能出现在后续包）
        if file_data:
            idx = last_result_idx.get(stream)
            if idx is None:
                continue
            # 只为 200 收集 body
            if results[idx].status != "200":
                continue

            # tshark 输出的 file_data 可能含奇怪字符；这里直接保留并截断
            # 注意：run_tshark 内部如果用了 errors="replace"，这里会很稳
            current = results[idx].body_preview
            combined = current + file_data
            results[idx].body_preview = _clip_text(combined, limit=1200)

    return results


def _print_summary(scanner_ip: str, scanner_name: str, results: List[ScanResult]) -> None:
    table = Table(title=f"Scan Summary - {scanner_ip} ({scanner_name})", show_lines=True)
    table.add_column("URL", overflow="fold")
    table.add_column("Status", justify="right")
    table.add_column("Body (only if 200)", overflow="fold")

    if not results:
        console.print(f"[bold red]No HTTP scan results reconstructed for {scanner_ip}.[/]")
        return

    for r in results:
        body = r.body_preview if r.status == "200" else ""
        table.add_row(r.url, r.status, body)

    console.print(table)


def main(pcap: str) -> None:
    info(f"Analyzing pcap (scan_result): {pcap}")

    scanners = detect_scanners(pcap)  # 复用你现有 scanner analyzer
    if not scanners:
        console.print("[bold red]No scanner candidates detected. Nothing to reconstruct.[/]")
        return

    for s in scanners:
        # 逐个 scanner ip 做复刻
        results = _analyze_http_scan_streaming(pcap, s.src_ip)
        _print_summary(s.src_ip, s.scanner, results)


