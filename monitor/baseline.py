"""
基线存档与差异对比 — 记录敏感区域的“干净”快照，比对异常改动
"""
import os
import json
import hashlib
import time

from config import BASELINE_FILE, RULE_WEIGHTS, SUSPICIOUS_SCORE


def save_baseline(snapshot, path=BASELINE_FILE):
    """把当前快照定为基线（带时间戳）"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {"saved_at": time.time(), "snapshot": snapshot}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, default=str)
    return payload["saved_at"]


def load_baseline(path=BASELINE_FILE):
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _hash(obj):
    """把任意可 JSON 化的对象哈希成稳定串，用于简单比对"""
    return hashlib.sha256(json.dumps(obj, default=str, sort_keys=True).encode()).hexdigest()


def diff_snapshot(current, baseline):
    """
    对比当前快照与基线，返回新增/变更的敏感项列表 [(区域, 描述, 风险规则名), ...]
    规则映射：先粗分区，再在引擎里替换为权重。
    """
    findings = []
    b = (baseline or {}).get("snapshot", {}) or {}

    # --- 注册表自启动 ---
    cur_auto = current.get("autostart", {})
    base_auto = b.get("autostart", {})
    base_runs = {k: v for k, v in base_auto.items() if k.startswith("run:")}
    for key, vals in cur_auto.items():
        if not key.startswith("run:"):
            continue
        old = base_runs.get(key, {})
        for name, val in vals.items():
            if name not in old or old[name] != val:
                findings.append((key, f"自启动项 {name}={val}", "registry_autostart_run"))

    # --- Winlogon / AppInit ---
    for key in ("winlogon", "appinit"):
        group = {k: v for k, v in base_auto.items()} if key == "winlogon" else \
                {k: v for k, v in base_auto.items()}
        cur_group = {k: v for k, v in cur_auto.items() if k.startswith(key + ":")}
        base_group = {k: v for k, v in base_auto.items() if k.startswith(key + ":")}
        for k, vals in cur_group.items():
            old = base_group.get(k, {})
            for name, val in vals.items():
                if name not in old or old[name] != val:
                    rule = "registry_autostart_winlogon" if key == "winlogon" else "registry_appinit"
                    findings.append((k, f"{key}项 {name}={val}", rule))

    # --- 服务启动类型变化 ---
    cur_svc = cur_auto.get("services", {})
    base_svc = base_auto.get("services", {})
    for svc, info in cur_svc.items():
        old = base_svc.get(svc)
        if old is None:
            # 新服务，且自启动
            if info.get("start") in (2, 0):
                findings.append(("services", f"新增自启服务 {svc}", "registry_services_autostart"))
        elif old.get("start") != info.get("start"):
            findings.append(("services", f"服务 {svc} 启动类型由{old.get('start')}改{info.get('start')}",
                             "registry_services_autostart"))

    # --- 启动目录新增 ---
    cur_sf = current.get("startup_folder", {})
    base_sf = b.get("startup_folder", {})
    for fp in cur_sf:
        if fp not in base_sf:
            findings.append(("startup_folder", f"启动目录新增 {fp}", "startup_folder_new"))

    # --- 计划任务新增/变更 ---
    cur_tasks = set(current.get("scheduled_tasks", {}))
    base_tasks = set(b.get("scheduled_tasks", {}))
    for t in sorted(cur_tasks - base_tasks):
        findings.append(("scheduled_tasks", f"新增计划任务 {t.partition('|')[0]}", "scheduled_task_susp"))

    # --- 载荷高发区新增 PE/脚本 ---
    cur_pay = set(current.get("payload_files", []))
    base_pay = set(b.get("payload_files", []))
    for fp in sorted(cur_pay - base_pay):
        findings.append(("payload", f"载荷区新增 {fp}", "payload_dir_new_pe"))

    return findings


def score_findings(findings):
    """把命中规则累计成 0-100 的风险分（按权重累加封顶）"""
    total = 0
    for _, _, rule in findings:
        total += RULE_WEIGHTS.get(rule, 0)
    return min(total, 100)


def verdict_from_score(score):
    """风险分 → 判定：<阈值 良性，>=阈值 可疑待审"""
    if score >= SUSPICIOUS_SCORE:
        return "可疑待审"
    return "良性"