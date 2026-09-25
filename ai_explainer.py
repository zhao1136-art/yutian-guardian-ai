"""
御天防护型 AI — 自研本地解释引擎（无外部大模型）
根据检测数据（四态融合 + 置信度 + 概率 + 监控风险项 + 特征知识库最近邻）
生成可控、可解释的自然语言结论 / 依据 / 处置建议，
并以关键字意图识别回答用户的常见追问。

数据驱动升级：可注入 CNN 嵌入(256维)，在特征知识库中检索最相似的历史训练样本，
作为“经验依据”并在回答中给出推理链。纯本地离线，不联网、无需 API Key。
"""
import re


# ============ 内部工具 ============

def _pct(x):
    """0~1 概率 → 百分比字符串"""
    try:
        return f"{float(x) * 100:.1f}%"
    except (TypeError, ValueError):
        return "--"


def _round(x):
    try:
        return round(float(x), 4)
    except (TypeError, ValueError):
        return None


# ============ 四态元数据 ============

_STATES = {
    "恶意": {
        "severity": "high",
        "head": "判定为【恶意】，风险高",
        "advice": [
            "立即隔离该文件（移动到受控沙箱，不要直接执行）。",
            "检查它是否被添加到自启动、计划任务或启动目录，并清理相关项。",
            "若已运行过，建议全盘查杀、重置受影响的账号与凭证，必要时重装系统。",
            "保留样本供分析与溯源，勿公开传播恶意载荷。",
        ],
    },
    "可疑待审": {
        "severity": "medium",
        "head": "判定为【可疑待审】，需人工复核",
        "advice": [
            "暂不要执行该文件，先在沙箱/虚拟机中分析行为。",
            "核对触发告警的监控风险项，确认是否为正常软件误报。",
            "确认来源是否可信；来源不明则按恶意样本处理。",
        ],
    },
    "良性": {
        "severity": "low",
        "head": "判定为【良性】，风险低",
        "advice": [
            "可正常使用，建议继续用监控层观察后续行为。",
            "若仍存疑，可在隔离环境中再复核一次。",
        ],
    },
    "未知": {
        "severity": "medium",
        "head": "无法给出确定结论【未知】，需进一步确认",
        "advice": [
            "该文件属于模型训练分布之外的陌生样本，静态置信度不足。",
            "建议先用沙箱运行观察，或补充特征后重新训练模型。",
            "不要仅凭未知结论直接放行，优先人工介入。",
        ],
    },
}

# 监控风险分档位说明
_SCORE_HINT = {
    0: "当前监控未见异常改动。",
    40: "达到【可疑待审】阈值，存在需要留意的敏感区改动。",
    70: "风险信号较强，建议重点排查。",
    100: "风险信号达到上限，视为高风险事件。",
}


def _hint_for_score(score):
    try:
        s = int(score)
    except (TypeError, ValueError):
        return ""
    if s == 0:
        return _SCORE_HINT[0]
    for thr in (100, 70, 40):
        if s >= thr:
            return f"风险分 {s}：{_SCORE_HINT[thr]}"
    return f"风险分 {s}：{_SCORE_HINT[0]}"


# ============ 数据驱动知识库 ============
# 惰性加载：首次需要时读一次特征知识库，做最近邻检索生成“经验依据”。

def _nearest_examples(embedding, k=3):
    """
    对指定 CNN 嵌入(256维)做特征知识库最近邻检索。
    返回结构化命中 dict 或 None（无嵌入/无库时）。
    命中结构: {"matches":[{rank,label,label_name,file,sha,score}],
               "by_label":{label:{best_score,label_name}}}
    """
    if not embedding:
        return None
    try:
        from models import knowledge
        kb = knowledge.load_knowledge()
        if not kb:
            return None
        return knowledge.retrieve(embedding, kb, k=k)
    except Exception:
        return None


# ============ 核心分析 ============

def analyze(detection, embedding=None):
    """
    输入 _predict 返回的检测 payload，生成结构化解释。
    detection 关键字段：
      fused_state, label, confidence, probabilities{benign,malware},
      monitor{risk_score, monitor_verdict, findings:[{area,desc,rule},...]}
    embedding：可选的 256 维 CNN 嵌入，用于数据驱动最近邻检索。
    返回 {fused_state, severity, summary, rationale, evidence[], advice[],
           score_hint, questions[], reasoning_chain[]}
    """
    detection = detection or {}
    state = detection.get("fused_state") or detection.get("label") or "未知"
    meta = _STATES.get(state, _STATES["未知"])
    probs = detection.get("probabilities") or {}
    conf = _round(detection.get("confidence"))
    mon = detection.get("monitor") or {}
    findings = mon.get("findings") or []
    risk = mon.get("risk_score")
    verdict = mon.get("monitor_verdict")

    lines = []
    evidence = []
    reasoning_chain = []

    # 1) 静态模型依据
    if probs.get("malware") is not None or probs.get("benign") is not None:
        ev = (f"静态模型：恶意概率 {_pct(probs.get('malware'))}，"
              f"良性概率 {_pct(probs.get('benign'))}"
              + (f"，模型置信度 {conf}" if conf is not None else ""))
        evidence.append(("静态分析", ev))
        lines.append(ev)
        reasoning_chain.append(("静态模型", round(probs.get("malware") or 0, 4)))

    # 2) 监控依据
    if verdict:
        evidence.append(("系统监控", f"监控判定：{verdict}（风险分 {risk}/100）"))
        lines.append(f"系统监控侧判定为【{verdict}】，风险分 {risk}/100。")
        reasoning_chain.append(("系统监控", verdict))
    if findings:
        tops = findings[:5]
        evidence.append(("命中风险项",
                         "；".join(f"[{f.get('area')}] {f.get('desc')}" for f in tops)))
        lines.append(f"共命中 {len(findings)} 项敏感区改动/风险项（示例如下）：")
        for f in tops:
            lines.append(f"  · [{f.get('area')}] {f.get('desc')}（规则：{f.get('rule')}）")

    # 3) 数据驱动：特征知识库最近邻（经验依据）
    hits = _nearest_examples(embedding) if embedding is not None else None
    if hits and hits.get("matches"):
        top = hits["matches"][:3]
        ev_exp = ("历史经验", "与特征知识库中最相近的 "
                  + "、".join(f"「{m.get('file','?')}」({m['label_name']}, 相似度 {m['score']})"
                             for m in top)
                  + "，共匹配 "
                  + str(len(hits['matches'])) + " 个候选。距离越近越像该历史样本。")
        evidence.append(("历史经验", ev_exp[1]))
        lines.append(f"特征知识库最近邻：{ev_exp[1]}")
        reasoning_chain.append(("知识库最近邻", top))

    # 4) 汇总
    summary = (f"{meta['head']}。"
               + (" ".join(lines[:1]) if lines else "当前未提供额外检测数据。"))
    if state in ("未知",):
        summary += " 由于落在训练分布之外，未给强结论。"

    return {
        "fused_state": state,
        "severity": meta["severity"],
        "summary": summary,
        "rationale": "\n".join(lines) if lines else "无额外分析依据。",
        "evidence": evidence,
        "advice": meta["advice"],
        "score_hint": _hint_for_score(risk),
        "questions": ["为什么这么判定", "有哪些依据", "我该怎么办", "风险高吗"],
        "reasoning_chain": reasoning_chain,
    }


# ============ 意图问答 ============

def _match_intent(question):
    q = (question or "").strip()
    if not q:
        return "default"
    if re.search(r"怎么办|处置|处理|应对|如何操作|建议", q):
        return "advice"
    if re.search(r"为什么|为何|咋|依据|证据|详情|详细|哪.*(检测|可疑|危险)|凭|理由", q):
        return "why"
    if re.search(r"风险|严重|危险|高不高|危害|影响", q):
        return "risk"
    if re.search(r"结论|结果|判断|判定|摘要|是什么|总结", q):
        return "summary"
    return "default"


def ask(question, detection, embedding=None):
    """根据用户问题与检测上下文，返回一段自然语言回答文本。"""
    a = analyze(detection, embedding=embedding)
    intent = _match_intent(question)
    state = a["fused_state"]

    if intent == "advice":
        body = "\n".join(f"{i}. {t}" for i, t in enumerate(a["advice"], 1))
        return f"{a['summary']}\n\n处置建议：\n{body}"
    if intent == "why":
        base = f"判定为【{state}】的依据如下：\n{a['rationale']}"
        if a.get("reasoning_chain"):
            ks = [f"{k}: {v}" for k, v in a["reasoning_chain"]
                  if not isinstance(v, list)]
            if ks:
                base += "\n\n推理链：" + " → ".join(ks)
        return base
    if intent == "risk":
        return (f"该样本严重程度：{a['severity']}"
                + (f"\n{a['score_hint']}" if a["score_hint"] else ""))
    if intent == "summary":
        return a["summary"]
    # default：给出结论 + 提示可问点什么
    qs = "、".join(a["questions"])
    return f"{a['summary']}\n\n你可以问我：{qs}，或上传文件让我先检测。"


# ============ 便捷入口 ============

def explain(detection, question=None, embedding=None):
    """对外统一入口：question 为空 → 返回 analyze()；否则 → ask()。
    若 detection 本身携带 embedding 字段，则自动透传给知识库检索。"""
    if embedding is None:
        embedding = (detection or {}).get("embedding")
    if question and question.strip():
        return {"ok": True, "fused_state": analyze(detection, embedding)["fused_state"],
                "reply": ask(question, detection, embedding=embedding)}
    a = analyze(detection, embedding)
    return {"ok": True, **a}