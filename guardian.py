"""
防护型 AI — 敏感区域监控入口
盯防系统敏感区域（自启动/启动目录/计划任务/服务/载荷区 + 事件日志），
融合成 良性 / 可疑待审 判定。复用 config + monitor 模块。

用法:
  python guardian.py init                     # 将当前状态定为干净基线
  python guardian.py audit                    # 审计：与基线比，报异常与风险分(+可选 --file 用CNN复核)
  python guardian.py monitor                  # 基线审计 + 最近事件日志，一次综合检查
  python guardian.py audit --file fp.exe      # 对某文件额外用 CNN 静态复核
"""
import os
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import MODEL_PATH, IMG_SIZE
from monitor import scanner, baseline, events, processmem


def _build_agent():
    """拼出由基线审计 + 事件日志 + 进程/内存监控命中的全部风险项与分数"""
    current = scanner.snapshot()
    stored = baseline.load_baseline()
    findings = baseline.diff_snapshot(current, stored)
    ev_hits = events.check_recent_events()
    for rule, desc in ev_hits:
        findings.append(("events", desc, rule))
    proc_hits = processmem.check()
    for hit in proc_hits:
        findings.append(hit)
    total = baseline.score_findings(findings)
    return current, findings, total


def cmd_init():
    snap = scanner.snapshot()
    t = baseline.save_baseline(snap)
    print(f"[监控] 已把当前敏感区域状态存为基线（{t:.0f}）")
    print(f"[监控] 自启动项/启动目录/服务/载荷区已采集")


def fuse(monitor_verdict, cnn_label):
    """
    融合 监控判定 + CNN 静态判定 → 最终四态：
      恶意 / 可疑待审 / 良性 / 未知(有文件复核但静态读不出→待人工)
    原则：强信号(恶意)优先；监控待审优先；无文件复核时以监控为准。
    """
    if cnn_label == "恶意":
        return "恶意"
    if monitor_verdict == "可疑待审":
        return "可疑待审"
    if cnn_label is not None and cnn_label in ("未知", "无法读取"):
        return "未知"
    return "良性"


def cmd_audit(args):
    current, findings, total = _build_agent()

    if current:
        pass  # 仅触发扫描（结果已在 findings 中）
    print("=" * 60)
    print("  防护型 AI — 敏感区域审计")
    print("=" * 60)

    if not findings:
        print("[监控] 敏感区域与基线一致，未发现异常改动。")
    else:
        print(f"[监控] 发现 {len(findings)} 项异常/风险：")
        for area, desc, rule in findings:
            print(f"   - [{area}] {desc}  (规则: {rule})")

    mon_verdict = baseline.verdict_from_score(total)
    print(f"[监控] 规则风险分: {total}/100   "
          f"判定: {mon_verdict}")

    # 可选：对若干文件做 CNN 静态复核 → 融合成最终四态
    cnn_label = None
    files = getattr(args, "file", None)
    if files:
        flist = files.split(",") if isinstance(files, str) else [files]
        for f in flist:
            lab = _cnn_review(f.strip())
            print(f"[CNN] 文件 {os.path.basename(f.strip())} 静态判定: {lab}")
            if lab == "恶意":
                cnn_label = "恶意"
            elif lab.startswith("未知"):
                cnn_label = "未知"
    print(f"[融合] 最终判定: {fuse(mon_verdict, cnn_label)}")
    return total


def cmd_monitor(args):
    total = cmd_audit(args)


def _cnn_review(file_path):
    """用训练好的 GuardianCNN 对单个 PE 做静态判定（含 OOD 未知，尽力而为，失败返回 '未知'）"""
    try:
        import torch
        from data.binary_to_image import file_to_image_tensor
        from models.cnn import GuardianCNN
        from models.ood import load_stats
        from config import OOD_STATS_FILE, OOD_MAHAL_THRESHOLD, OOD_CONF_THRESHOLD
        from infer import predict_tensor
        if not os.path.isfile(file_path):
            return "未知(文件不存在)"
        cp = torch.load(MODEL_PATH, map_location="cpu", weights_only=False)
        model = GuardianCNN(input_size=cp.get("img_size", IMG_SIZE))
        model.load_state_dict(cp["model_state_dict"])
        model.eval()
        t = file_to_image_tensor(file_path, cp.get("img_size", IMG_SIZE))
        if t is None:
            return "未知(转换失败)"
        ood_stats = load_stats(OOD_STATS_FILE)
        label, _, _ = predict_tensor(
            model, t, cp.get("img_size", IMG_SIZE), "cpu",
            ood_stats=ood_stats,
            mahal_threshold=OOD_MAHAL_THRESHOLD, conf_threshold=OOD_CONF_THRESHOLD,
        )
        return label
    except Exception:
        return "未知(CNN加载失败)"


def main():
    parser = argparse.ArgumentParser(description="防护型 AI — 敏感区域监控")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="将当前状态存为干净基线")
    pa = sub.add_parser("audit", help="与基线比对做审计")
    pa.add_argument("--file", default=None, help="附带用 CNN 复核的 PE 文件")
    sub.add_parser("monitor", help="审计 + 最近事件日志综合检查")

    args = parser.parse_args()
    if args.cmd == "init":
        cmd_init()
    elif args.cmd == "audit":
        cmd_audit(args)
    elif args.cmd == "monitor":
        cmd_monitor(args)


if __name__ == "__main__":
    main()