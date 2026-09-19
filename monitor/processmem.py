"""
进程/内存监控源 — 调用精简后的 memtool（纯 CLI 只读采样器）获取进程全景，
据此发现疑似伪装进程名、以及内存异常偏高的进程，返回风险项供融合判定。

属于“防护型 AI”监控模块的一路数据源（只读，不改动任何进程）。
"""
import os
import sys
import subprocess
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import MEMTOOL_PATH, HIGH_WS_MB, SUSP_PROC_NAMES


def _snapshot():
    """运行 memtool --snapshot 取 JSON；失败/无工具返回 None"""
    if not MEMTOOL_PATH or not os.path.isfile(MEMTOOL_PATH):
        return None
    try:
        out = subprocess.run(
            [MEMTOOL_PATH, "--snapshot"],
            capture_output=True, text=True, timeout=20,
            encoding="utf-8", errors="replace",
        )
        data = json.loads(out.stdout)
        return data
    except Exception:
        return None


def _name_suspicious(name):
    """进程名是否命中疑似伪装/变体名单（大小写不敏感，末尾空格不影响）"""
    if not name:
        return False
    low = name.lower().strip()
    return low in {n.lower() for n in SUSP_PROC_NAMES}


def check():
    """
    返回风险项列表 [(区域, 描述, 规则名), ...]
    只读，不改动任何进程。
    """
    snapshot = _snapshot()
    if snapshot is None:
        return []
    findings = []
    procs = snapshot.get("processes", [])
    for p in procs:
        name = p.get("name", "")
        pid = p.get("pid")
        ws = p.get("ws_mb", 0.0) or 0.0
        if _name_suspicious(name):
            findings.append(
                ("process", f"疑似伪装进程名: {name} (PID {pid})", "proc_susp_name"))
        elif ws >= HIGH_WS_MB:
            # 只对非白名单(常见大内存软件)的进程补一个内存异常标记
            base = name.lower().replace(".exe", "")
            whitelist = {"system", "registry", "chrome", "msedge",
                         "discord", "searchapp", "searchindexer", "trae",
                         "solo", "code", "hybrid", "webs",
                         "windowsinternal", "complus"}
            if not any(base.startswith(tok) for tok in whitelist):
                findings.append(
                    ("process", f"内存异常偏高: {name} ws={ws:.0f}MB (PID {pid})",
                     "proc_high_ws"))
    return findings