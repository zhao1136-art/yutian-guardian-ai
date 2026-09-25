"""
特征知识库 — 用训练样本的 CNN 嵌入构建"经验记忆"
检测时把待检样本的嵌入与知识库中真实历史样本做最近邻匹配，
输出最相似的历史样本作为"经验依据"，使 ai_explainer 能给出数据驱动的推理链。

数据来源：seal_samples 封存包（AES-256 加密）内存读取，不落明文。
落盘产物：
  checkpoints/knowledge.npz      每类嵌入矩阵 (N, OOD_EMBED_DIM)
  checkpoints/knowledge_meta.json 每条样本的文件名/类标/sha256
"""
import os
import json
import hashlib
import numpy as np

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import OOD_EMBED_DIM, CHECKPOINT_DIR

KB_FEATURES = os.path.join(CHECKPOINT_DIR, "knowledge.npz")
KB_META = os.path.join(CHECKPOINT_DIR, "knowledge_meta.json")

_LABEL_NAMES = {0: "良性", 1: "恶意"}


def sha256_bytes(raw):
    h = hashlib.sha256()
    h.update(raw)
    return h.hexdigest()


def save_knowledge(features, meta, path=KB_FEATURES, meta_path=KB_META):
    """
    落盘知识库。
    features: {label_int: (N, D) ndarray}
    meta:     {label_int: [{file, sha}, ...]}  顺序与 features 行一致
    返回 (path, meta_path)
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    arrays = {}
    for label, mat in features.items():
        arrays["feat_%d" % label] = np.asarray(mat, dtype=np.float32)
    np.savez(path, **arrays)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=1)
    return path, meta_path


def load_knowledge(path=KB_FEATURES, meta_path=KB_META):
    """
    加载知识库。文件缺失返回 None。
    返回 {"features": {label:(N,D)}, "meta": {label:[...]}}
    """
    if not os.path.isfile(path) or not os.path.isfile(meta_path):
        return None
    z = np.load(path)
    features = {}
    for key in z.files:
        label = int(key.split("_", 1)[1])
        features[label] = z[key]
    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)
    for k, arr in meta.items():
        if not isinstance(arr, list):
            meta[k] = []
    return {"features": features, "meta": meta}


def normalize(x):
    """L2 归一化，用于余弦相似度。"""
    x = np.asarray(x, dtype=np.float32)
    n = np.linalg.norm(x)
    return x / n if n > 0 else x


def retrieve(embedding, kb, k=3):
    """
    在知识库中检索与 embedding 最相似的历史样本。
    返回 None（无库）或:
      {"matches": [{label, label_name, file, sha, score, rank}...],
       "by_label": {label: best, ...}}
    score 为余弦相似度（0~1，越大越像）。
    """
    if not kb:
        return None
    emb = np.asarray(embedding, dtype=np.float32).reshape(-1)
    q = normalize(emb)
    matches = []
    results = {}
    qn = np.linalg.norm(q)
    if qn <= 0:
        return None
    q = q / qn
    for label, mat in kb["features"].items():
        if mat.shape[0] == 0:
            continue
        # 对矩阵行做 L2 归一化 → 点积即余弦相似度
        norms = np.linalg.norm(mat, axis=1)
        norms[norms == 0] = 1.0
        mat_n = mat / norms[:, None]
        sims = mat_n @ q
        order = np.argsort(-sims)[:k]
        best_score = -1.0
        meta_list = meta_of(kb, label)
        for rank, idx in enumerate(order, 1):
            score = float(sims[idx])
            rec = {"rank": rank, "score": round(score, 4),
                   "label": int(label),
                   "label_name": _LABEL_NAMES.get(int(label), str(label))}
            if int(idx) < len(meta_list):
                item = meta_list[int(idx)]
                rec["file"] = item.get("file", "") if isinstance(item, dict) else item
                rec["sha"] = item.get("sha", "") if isinstance(item, dict) else ""
            matches.append(rec)
            if score > best_score:
                best_score = score
        results[int(label)] = {"best_score": round(best_score, 4),
                               "label_name": _LABEL_NAMES.get(int(label), str(label))}
    matches.sort(key=lambda r: -r["score"])
    return {"matches": matches, "by_label": results}


def meta_of(kb, label):
    """取某类样本元数据列表，兼容 str/int key。"""
    m = kb.get("meta") or {}
    for key in (str(label), label):
        arr = m.get(key)
        if isinstance(arr, list):
            return arr
    return []


def build_memory_from_embeddings(emb_per_label, files_per_label):
    """
    ai_explainer 推理期一次性构建"当前样本的记忆锚点"，避免逐次全表扫描时
    标注文件名信息缺失。emb_per_label: {label:(N,D)}，files_per_label: {label:[file,]}。
    """
    features = {lbl: np.asarray(mat, dtype=np.float32) for lbl, mat in emb_per_label.items()}
    meta = {str(lbl): [{"file": f, "sha": ""} for f in files] if files else []
            for lbl, files in files_per_label.items()}
    return {"features": features, "meta": meta}


if __name__ == "__main__":
    demo = {0: np.random.randn(5, OOD_EMBED_DIM).astype(np.float32),
            1: np.random.randn(3, OOD_EMBED_DIM).astype(np.float32)}
    demo_meta = {0: [{"file": "b%d" % i, "sha": ""} for i in range(5)],
                 1: [{"file": "m%d" % i, "sha": ""} for i in range(3)]}
    kb = build_memory_from_embeddings(demo, demo_meta)
    hit = retrieve(demo[1][0], kb, k=2)
    print("最近邻命中:", [(m["label_name"], m["file"], m["score"]) for m in hit["matches"]])
    print("按类最优:", hit["by_label"])
    print("knowledge 模块冒烟测试通过")