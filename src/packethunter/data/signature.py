
from __future__ import annotations


UA_SIGNATURES: dict[str, list[str]] = {
    "nmap": ["nmap", "nmap scripting engine"],
    "nikto": ["nikto"],
    "sqlmap": ["sqlmap"],
    "acunetix": ["acunetix"],
    "nessus": ["nessus"],
    "gobuster": ["gobuster"],
    "dirbuster": ["dirbuster"],
    "curl": ["curl/"],
    "python-requests": ["python-requests"],
}


SCAN_THRESHOLDS = {
    "min_syn": 20,        # 原来 50 很容易“一个都没结果”
    "min_ports": 10,      # 原来 20 也容易没结果
    "min_hosts": 2,       # 扫多个内网主机时可用
}


TOPK_DEFAULT = 10
