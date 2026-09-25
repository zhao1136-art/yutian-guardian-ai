"""
守卫者 AI — 公用 LAN REST API 端口
提供鉴权后的模型检测与系统监控接口，方便其他程序/设备接入。

端点:
  GET  /health              健康检查（无鉴权）
  GET  /monitor             拉取敏感区域监控结果（需鉴权）
  POST /predict             上传文件做融合判定（需鉴权，multipart 的 file 字段）

鉴权: 需在请求头带 `Authorization: Bearer <token>`；
token 取环境变量 GUARDIAN_API_TOKEN，为空则自动生成并存 monitor_data/api_token.txt。

用法:
  python api_server.py                # 默认 0.0.0.0:8567
  python api_server.py --host 0.0.0.0 --port 8567
"""
import os
import sys
import json
import hmac
import time
import secrets
import traceback
import mimetypes
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import (API_HOST, API_PORT, API_MAX_UPLOAD, MONITOR_DIR,
                    MODEL_PATH, IMG_SIZE, STATIC_WEB)

# ---------- token 管理 ----------
TOKEN_FILE = os.path.join(MONITOR_DIR, "api_token.txt")


def resolve_token():
    """获取鉴权 token：优先环境变量，否则自动生成并持久化。"""
    env = os.environ.get("GUARDIAN_API_TOKEN", "").strip()
    if env:
        return env
    # 幂等：若已存在则复用
    if os.path.isfile(TOKEN_FILE):
        tok = open(TOKEN_FILE, encoding="utf-8").read().strip()
        if tok:
            return tok
    tok = secrets.token_urlsafe(28)
    os.makedirs(MONITOR_DIR, exist_ok=True)
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        f.write(tok)
    return tok


class _ServerState:
    """惰性持有重型对象（模型/监控），避免启动即加载的等待。"""
    model = None
    img_size = IMG_SIZE
    ood_stats = None
    started_at = time.time()
    # 最近一次检测的 CNN 嵌入，供 /explain 知识库检索复用
    last_embedding = None


def _load_runtime():
    """加载 CNN 模型 + OOD 统计（只做一次）。失败时置 None。"""
    import torch
    from models.cnn import GuardianCNN
    from models.ood import load_stats as ood_load
    from config import OOD_STATS_FILE
    if _ServerState.model is not None:
        return True
    cp = torch.load(MODEL_PATH, map_location="cpu", weights_only=False)
    sz = cp.get("img_size", IMG_SIZE)
    model = GuardianCNN(input_size=sz)
    model.load_state_dict(cp["model_state_dict"])
    model.eval()
    _ServerState.model = model
    _ServerState.img_size = sz
    _ServerState.ood_stats = ood_load(OOD_STATS_FILE)
    return True


def _json(data, handler, status=200):
    body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def _send_static(handler, path, status=200):
    """发送静态文件（带 CORS 头）。path 为磁盘绝对路径。
    托管 index.html 时自动注入鉴权 token 脚本，前端无需手动输入。"""
    ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
    with open(path, "rb") as f:
        body = f.read()
    if path.endswith("index.html"):
        tok = resolve_token()
        script = ("<script>"
                  "(function(){try{localStorage.setItem('guardian_token',%s)"
                  "}catch(e){}})()"
                  "</script>") % (json.dumps(tok),)
        marker = b"</head>"
        if marker in body:
            body = body.replace(marker, (script + "</head>").encode("utf-8"), 1)
        else:
            body = body + script.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.end_headers()
    handler.wfile.write(body)


def _resolve_static(rel_path):
    """把 URL 相对路径映射到 STATIC_WEB 下磁盘文件；不存在则回退 index.html。"""
    if not STATIC_WEB or not os.path.isdir(STATIC_WEB):
        return None
    rel = urllib.parse.unquote(rel_path).lstrip("/")
    if not rel or rel.endswith("/"):
        rel = "index.html"
    candidate = os.path.normpath(os.path.join(STATIC_WEB, rel))
    # 防目录穿越
    if not os.path.abspath(candidate).startswith(os.path.abspath(STATIC_WEB)):
        return None
    if os.path.isfile(candidate):
        return candidate
    index = os.path.join(STATIC_WEB, "index.html")
    return index if os.path.isfile(index) else None


def _monitor_payload():
    """运行监控层，返回 findings + 风险分 + 判定。失败返回空结构。"""
    try:
        from monitor import scanner, baseline, events, processmem
        current = scanner.snapshot()
        stored = baseline.load_baseline()
        findings = baseline.diff_snapshot(current, stored)
        for rule, desc in events.check_recent_events():
            findings.append(("events", desc, rule))
        for hit in processmem.check():
            findings.append(hit)
        total = baseline.score_findings(findings)
        return {
            "findings": [{"area": a, "desc": d, "rule": r}
                         for a, d, r in findings],
            "risk_score": total,
            "monitor_verdict": baseline.verdict_from_score(total),
        }
    except Exception as exc:
        return {"findings": [], "risk_score": 0,
                "monitor_verdict": "未就绪", "error": "监控采集异常",
                "detail": repr(exc)}


class GuardianHandler(BaseHTTPRequestHandler):
    server_version = "GuardianAPI/1.0"

    # ---- 鉴权 ----
    def _authed(self):
        """校验 Authorization: Bearer <token>，失败直接回 401 并返回 False。"""
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            _json({"error": "缺少 Bearer token", "code": "no_token"},
                  self, status=401)
            return False
        provided = header[len("Bearer "):].strip()
        if not hmac.compare_digest(provided, resolve_token()):
            _json({"error": "token 无效", "code": "bad_token"},
                  self, status=401)
            return False
        return True

    # ---- 路由 ----
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/health":
            self._health()
        elif path == "/monitor":
            if self._authed():
                self._monitor()
        else:
            # 非 API 路径：托管前端控制台静态资源（SPA 回退）
            static = _resolve_static(path)
            if static is None:
                _json({"error": "未找到接口", "code": "not_found"}, self, status=404)
            else:
                _send_static(self, static)

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/predict":
            if self._authed():
                self._predict()
        elif path == "/explain":
            if self._authed():
                self._explain()
        else:
            _json({"error": "未找到接口", "code": "not_found"}, self, status=404)

    # ---- 具体实现 ----
    def _health(self):
        ready = _ServerState.model is not None
        _json({
            "status": "ok" if ready else "model_not_ready",
            "model_ready": ready,
            "uptime_sec": int(time.time() - _ServerState.started_at),
        }, self)

    def _monitor(self):
        payload = _monitor_payload()
        payload["model_ready"] = _ServerState.model is not None
        _json(payload, self)

    def _predict(self):
        try:
            _load_runtime()
        except Exception:
            _json({"error": "模型加载失败，请先训练", "code": "model_fail"},
                  self, status=503)
            return
        if _ServerState.model is None:
            _json({"error": "模型未就绪，请先训练", "code": "model_not_ready"},
                  self, status=503)
            return

        # 读取上传的 file 字段
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > API_MAX_UPLOAD:
            # 拒绝超大/空请求：先标记关闭连接，避免请求体未读完时
            # 连接被重置（代理层表现为浏览器 "Failed to fetch"）
            self.close_connection = True
            _json({"error": "请求体为空或超出大小上限（%dMB）"
                   % (API_MAX_UPLOAD // (1024 * 1024)),
                   "code": "bad_length"}, self, status=400)
            return
        try:
            content_type = self.headers.get("Content-Type", "")
            if "multipart/form-data" in content_type:
                data = self._read_multipart(length)
            else:
                data = self.rfile.read(length)
        except Exception:
            _json({"error": "请求体读取失败", "code": "read_fail"}, self,
                  status=400)
            return
        if not data:
            _json({"error": "未收到文件内容", "code": "empty"}, self,
                  status=400)
            return

        # 转灰度 tensor
        import numpy as np
        from data.binary_to_image import array_to_square_image
        import torch
        arr = np.frombuffer(data, dtype=np.uint8)
        img = array_to_square_image(arr, _ServerState.img_size)
        tensor = torch.from_numpy(img).float().unsqueeze(0) / 255.0

        # 静态判定（CNN + OOD）
        from infer import predict_tensor
        from config import OOD_MAHAL_THRESHOLD, OOD_CONF_THRESHOLD
        label, conf, probs = predict_tensor(
            _ServerState.model, tensor, _ServerState.img_size, "cpu",
            ood_stats=_ServerState.ood_stats,
            mahal_threshold=OOD_MAHAL_THRESHOLD,
            conf_threshold=OOD_CONF_THRESHOLD,
        )

        # 提取 CNN 嵌入（256维），供特征知识库最近邻检索
        try:
            with torch.no_grad():
                emb_vec = _ServerState.model.embed(tensor.unsqueeze(0)).squeeze(0).tolist()
            _ServerState.last_embedding = emb_vec
        except Exception:
            emb_vec = None

        # 特征签名检测（MD5 哈希库 + 字节签名库）
        from sigscan import scan as sig_scan
        sig = sig_scan(data)

        # 监控融合
        mon = _monitor_payload()
        from guardian import fuse
        fused = fuse(mon["monitor_verdict"], label)
        if sig.get("malicious"):
            fused = "恶意"  # 强信号(特征签名命中)优先
        # 嵌入空间 2D 投影（供前端散点图；无知识库时为 None）
        viz = None
        if emb_vec:
            try:
                from viz_pca import build_viz
                viz = build_viz(emb_vec)
            except Exception:
                viz = None
        _json({
            "label": label,
            "confidence": round(conf, 4),
            "probabilities": {"benign": round(probs["benign"], 4),
                              "malware": round(probs["malware"], 4)},
            "fused_state": fused,
            "monitor": mon,
            "signature": sig,
            "embedding": emb_vec,
            "viz": viz,
        }, self)

    def _explain(self):
        """POST /explain — 自研本地解释引擎：根据检测结果生成结论/依据/建议，或回答追问。
        请求 JSON: {message?, detection_context?}  （均为可选；message 为空时返回完整分析）"""
        try:
            from ai_explainer import explain
        except Exception:
            _json({"error": "解释引擎加载失败", "code": "explainer_fail"}, self,
                  status=503)
            return
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > API_MAX_UPLOAD:
            _json({"error": "请求体为空或超出大小上限", "code": "bad_length"}, self,
                  status=400)
            return
        try:
            raw = self.rfile.read(length).decode("utf-8", "ignore")
            payload = json.loads(raw) if raw.strip() else {}
        except Exception:
            _json({"error": "请求体不是合法 JSON", "code": "bad_json"}, self,
                  status=400)
            return
        message = payload.get("message")
        chat_history = payload.get("chat_history") or []
        detection = payload.get("detection_context") or {}
        if not detection:
            detection = {"fused_state": "未知", "probabilities": {},
                         "monitor": {"risk_score": 0, "findings": []}}
        # 数据驱动：若未携带嵌入，则复用最近一次 predict 的嵌入做知识库检索
        if not detection.get("embedding") and _ServerState.last_embedding:
            detection["embedding"] = _ServerState.last_embedding
        result = explain(detection, message, chat_history=chat_history)
        # 附加与历史样本最相似的最近邻（供前端展示"像谁"）
        try:
            if detection.get("embedding"):
                from models import knowledge as KB
                kb = KB.load_knowledge()
                if kb:
                    hits = KB.retrieve(detection["embedding"], kb, k=3)
                    if hits:
                        result["top_matches"] = hits["matches"]
        except Exception:
            pass
        _json(result, self)

    def _read_multipart(self, length):
        """粗解析 multipart/form-data，返回第一个 file 字段的二进制内容。"""
        raw = self.rfile.read(length)
        boundary_line = self.headers.get("Content-Type", "").split("boundary=")[-1].strip()
        boundary = ("--" + boundary_line).encode()
        # 找到第一个文件内容
        parts = raw.split(boundary)
        for part in parts:
            # 每个 part 形如 [headers]\r\n\r\n[data]\r\n
            sep = part.find(b"\r\n\r\n")
            if sep == -1:
                continue
            header_blob = part[:sep]
            if "filename=" in header_blob.decode("utf-8", "ignore") or \
               b"content-type" in header_blob.lower():
                data = part[sep + 4:]
                # 去掉末尾的 \r\n-- 分隔符残余
                return data.rstrip(b"\r\n-- -")
        return b""


def main():
    import argparse
    ap = argparse.ArgumentParser(description="守卫者 AI — LAN REST API")
    ap.add_argument("--host", default=API_HOST)
    ap.add_argument("--port", type=int, default=API_PORT)
    args = ap.parse_args()

    tok = resolve_token()
    print("=" * 56)
    print("  守卫者 AI — 公用 API 端口")
    print("=" * 56)
    print(f"监听: http://{args.host}:{args.port}")
    print(f"token 位于: {TOKEN_FILE}  (或环境变量 GUARDIAN_API_TOKEN)")
    print("接口:")
    print("  GET  /health    健康检查(无需鉴权)")
    print("  GET  /monitor   监控结果(需 Bearer token)")
    print("  POST /predict   文件融合判定(需 Bearer token)")
    print("  POST /explain   自研本地解释引擎(需 Bearer token)")
    if os.path.isdir(STATIC_WEB):
        print(f"  控制台    /   (托管控件: {STATIC_WEB})")

    server = ThreadingHTTPServer((args.host, args.port), GuardianHandler)
    print(f"\n服务已启动，按 Ctrl+C 停止。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
        server.server_close()


if __name__ == "__main__":
    main()