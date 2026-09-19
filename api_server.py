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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import (API_HOST, API_PORT, API_MAX_UPLOAD, MONITOR_DIR,
                    MODEL_PATH, IMG_SIZE)

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
    handler.end_headers()
    handler.wfile.write(body)


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
    except Exception:
        return {"findings": [], "risk_score": 0,
                "monitor_verdict": "未就绪", "error": "监控采集异常"}


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
    def do_GET(self):
        if self.path.split("?")[0] == "/health":
            self._health()
        elif self.path.split("?")[0] == "/monitor":
            if self._authed():
                self._monitor()
        else:
            _json({"error": "未找到接口", "code": "not_found"}, self, status=404)

    def do_POST(self):
        if self.path.split("?")[0] == "/predict":
            if self._authed():
                self._predict()
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
            _json({"error": "请求体为空或超出大小上限", "code": "bad_length"},
                  self, status=400)
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

        # 监控融合
        mon = _monitor_payload()
        from guardian import fuse
        fused = fuse(mon["monitor_verdict"], label)
        _json({
            "label": label,
            "confidence": round(conf, 4),
            "probabilities": {"benign": round(probs["benign"], 4),
                              "malware": round(probs["malware"], 4)},
            "fused_state": fused,
            "monitor": mon,
        }, self)

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

    server = ThreadingHTTPServer((args.host, args.port), GuardianHandler)
    print(f"\n服务已启动，按 Ctrl+C 停止。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
        server.server_close()


if __name__ == "__main__":
    main()