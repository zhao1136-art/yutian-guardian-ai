"""
敏感区域扫描器 — 枚举自启动项/启动目录/计划任务/服务/载荷高发区

这是“防护型 AI”监控模块的一部分：把需要盯防的系统敏感区域，
统一采集成一个快照 dict，供基线比对与规则打分使用。
"""
import os
import sys
import winreg

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import PAYLOAD_DIRS


# ---------- 注册表自启动 ----------
_AUTOSTART_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]
_WINLOGON_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
]
_APPINIT_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"),
]
# 服务自启（比直接改 ImagePath 更隐蔽）：检查这些服务关键是否自动启动
_SERVICES_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
]


def _read_values(root, subkey):
    """读出某注册表项的所有 (名称, 数据)，失败返回 {}；值统一转字符串便于稳定比对"""
    out = {}
    try:
        with winreg.OpenKey(root, subkey) as k:
            n = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, n)
                    out[name] = str(val)
                    n += 1
                except OSError:
                    break
    except OSError:
        pass
    return out


def snapshot_autostart():
    """采集自启动相关注册表：Run/RunOnce、Winlogon、AppInit、服务自启"""
    data = {}
    for root, subkey in _AUTOSTART_KEYS:
        data[f"run:{subkey}"] = _read_values(root, subkey)
    for root, subkey in _WINLOGON_KEYS:
        data[f"winlogon:{subkey}"] = _read_values(root, subkey)
    for root, subkey in _APPINIT_KEYS:
        data[f"appinit:{subkey}"] = _read_values(root, subkey)
    # 服务：仅记录自启动 + 可执行路径，避免快照过大
    services = {}
    for root, subkey in _SERVICES_KEYS:
        try:
            with winreg.OpenKey(root, subkey) as k:
                i = 0
                while True:
                    try:
                        svc = winreg.EnumKey(k, i)
                        i += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(root, subkey + "\\" + svc) as sk:
                            start_val = winreg.QueryValueEx(sk, "Start")[0]
                            img = winreg.QueryValueEx(sk, "ImagePath")[0]
                            services[svc] = {"start": start_val, "image": str(img)}
                    except OSError:
                        continue
        except OSError:
            pass
    data["services"] = services
    return data


def get_startup_dirs():
    """启动文件夹相关目录（用户 + 公共）"""
    dirs = []
    base = os.environ.get("APPDATA")
    if base:
        dirs.append(os.path.join(base, r"Microsoft\Windows\Start Menu\Programs\Startup"))
    pub = (os.environ.get("PROGRAMDATA")
           or r"C:\ProgramData")
    dirs.append(os.path.join(pub, r"Microsoft\Windows\Start Menu\Programs\Startup"))
    return [d for d in dirs if os.path.isdir(d)]


def list_startup_folder():
    """列出启动文件夹内所有文件（名称+大小+校验用 mtime）"""
    items = {}
    for d in get_startup_dirs():
        try:
            for name in os.listdir(d):
                fp = os.path.join(d, name)
                items[fp] = os.path.getmtime(fp)
        except OSError:
            continue
    return items


def list_scheduled_tasks():
    """枚举计划任务，返回 {任务路径: 状态}；忽略“下次运行时间”等易变列避免误报"""
    tasks = {}
    try:
        import subprocess
        out = subprocess.run(["schtasks", "/query", "/fo", "csv", "/nh"],
                             capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return tasks
    for ln in out.splitlines():
        # 格式: 任务名,下次运行时间,模式,状态  —— 只取首列(名)和末列(状态)
        parts = ln.split(",")
        if len(parts) >= 4:
            name = parts[0].strip()
            status = parts[-1].strip()
            tasks[f"{name}|{status}"] = None
    return tasks


def list_payload_dir_pe():
    """在载荷高发区找近期出现的 PE/脚本文件（名称+大小），白名单只返回路径列表"""
    found = []
    exts = {".exe", ".dll", ".scr", ".com", ".bat", ".vbs", ".ps1", ".js", ".cmd"}
    for template in PAYLOAD_DIRS:
        d = os.path.expandvars(template)
        if not os.path.isdir(d):
            continue
        try:
            for name in os.listdir(d):
                if os.path.splitext(name)[1].lower() in exts:
                    fp = os.path.join(d, name)
                    found.append(fp)
        except OSError:
            continue
    return found


def snapshot():
    """采集整份敏感区域快照（用于基线存档/审计）"""
    return {
        "autostart": snapshot_autostart(),   # 含注册表与服务
        "startup_folder": list_startup_folder(),
        "scheduled_tasks": list_scheduled_tasks(),
        "payload_files": list_payload_dir_pe(),
    }