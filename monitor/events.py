"""
事件日志监控（准实时） — 读取最近一段时间的安全/系统事件，发现可疑进程/服务动作

属于“防护型 AI”监控模块的实时档。依赖系统事件日志（无需内核驱动，
尽力而为：读不到就静默跳过，不影响基线审计）。
"""
import time
import datetime
import subprocess

from config import EVENT_LOOKBACK_MINUTES

# 关注的 Windows 安全事件：
#   4688 = 新进程创建（关键属性：命令行）
#   7045 = 安装新服务
#   4697 = 服务安装
_WATCHED_EVENT_IDS = {"4688", "7045", "4697"}
_SUSPICIOUS_CMDS = ("powershell -", "cmd /c", "certutil", "roundtab", "mshta",
                    "regsvr32", "schtasks /create", "wmic process call create")


def query_events(since_minutes=EVENT_LOOKBACK_MINUTES):
    """
    用 wevtutil 拉取最近 since_minutes 分钟的安全/系统事件，返回风险命中列表
    每条命中: (事件ID, 描述)
    """
    since = datetime.datetime.now() - datetime.timedelta(minutes=since_minutes)
    query = f"*[System[(EventID={'] or EventID='.join(sorted(_WATCHED_EVENT_IDS))}) and " \
            f"TimeCreated[timediff(@SystemTime) <= {since_minutes*60000}]]]"
    findings = []
    for log in ("Security", "System"):
        try:
            out = subprocess.run(
                ["wevtutil", "qe", log, "/q:" + query, "/f:text", "/c:50"],
                capture_output=True, text=True, timeout=30).stdout
        except Exception:
            continue
        for evt in _parse(out):
            findings.append(evt)
    return findings


def _parse(text):
    """从 wevtutil 文本输出里粗略提取事件ID+描述"""
    results = []
    cur_id = None
    buf = []
    for ln in text.splitlines():
        s = ln.strip()
        if s.lower().startswith("event["):
            if cur_id and buf:
                info = " ".join(buf)
                results.append((cur_id, info))
            cur_id = None
            buf = []
        elif s.startswith("Event ID:"):
            cur_id = s.split(":", 1)[1].strip()
        elif s.startswith("Description:"):
            buf.append(s.split(":", 1)[1].strip())
        elif buf and s:
            buf.append(s)
    if cur_id and buf:
        results.append((cur_id, " ".join(buf)))
    return [(eid, desc) for eid, desc in results if eid in _WATCHED_EVENT_IDS]


def check_recent_events():
    """返回最近事件中的风险项列表 [(规则名, 描述)]"""
    hits = []
    try:
        for eid, desc in query_events():
            low = desc.lower()
            if any(k in low for k in _SUSPICIOUS_CMDS):
                hits.append(("event_process_susp", f"事件{eid}: {desc[:120]}"))
    except Exception:
        pass
    return hits