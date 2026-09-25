"""
嵌入空间 2D 投影模块 — 用知识库(KB)样本特征拟合 PCA(降到2维)，
把当前检测样本的 256 维 embedding 投影成散点图坐标，供前端直观展示
"这个样本离恶意/良性历史样本簇有多远"。

用法: from viz_pca import project_sample, get_clusters
依赖: 仅 numpy + models.knowledge(不改动)
"""
import os
import sys
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from models import knowledge as KB

_MAX_POINTS_PER_CLASS = 250  # 每类最多返回的簇点个数（保持簇形、控制体积）


class _PcaCache:
    """进程内缓存：投影矩阵 + 各类投影点。"""
    projection = None    # (2, D) 投影矩阵
    mean = None          # (D,) 训练均值
    points = {0: None, 1: None}   # label -> (N, 2)
    ready = False


def _load_and_fit():
    """加载 KB 特征并拟合 PCA(2D)。成功返回 True，KB 缺失返回 False。"""
    kb = KB.load_knowledge()
    if not kb:
        return False
    feats = kb.get("features") or {}
    mats = []
    for label in (0, 1):
        m = feats.get(label)
        if m is not None and m.shape[0] > 0:
            mats.append(np.asarray(m, dtype=np.float32))
    if len(mats) < 2:
        return False
    X = np.vstack(mats)
    # 去中心化 + SVD 取前 2 个右奇异向量 → 投影矩阵 (2, D)
    mean = X.mean(axis=0)
    Xc = X - mean
    _, _, Vt = np.linalg.svd(Xc, full_matrices=False)
    proj = Vt[:2].astype(np.float32)   # (2, D)
    P = proj @ Xc.T                    # (2, N) 全量投影（用于采样簇点）
    _PcaCache.projection = proj
    _PcaCache.mean = mean.astype(np.float32)
    _PcaCache.points = {}
    start = 0
    for label in (0, 1):
        m = feats.get(label)
        n = m.shape[0] if m is not None else 0
        _PcaCache.points[label] = P[:, start:start + n].T if n else None
        start += n
    _PcaCache.ready = True
    return True


def _ensure():
    if not _PcaCache.ready:
        _load_and_fit()
    return _PcaCache.ready


def project_sample(embedding):
    """把单个 embedding 投影为 {x, y}；无 KB/失败返回 None。"""
    if not _ensure():
        return None
    emb = np.asarray(embedding, dtype=np.float32).reshape(-1)
    if emb.shape[0] != _PcaCache.mean.shape[0]:
        return None
    xy = (_PcaCache.projection @ (emb - _PcaCache.mean)).tolist()
    return {"x": round(xy[0], 4), "y": round(xy[1], 4)}


def get_clusters():
    """返回前端散点图所需的簇点列表（每类均匀采样 ≤250 个）。"""
    if not _ensure():
        return None
    out = []
    colors = {1: "#e5484d", 0: "#30a46c"}   # 恶意红 / 良性绿
    for label, points in _PcaCache.points.items():
        if points is None or points.shape[0] == 0:
            continue
        n = points.shape[0]
        if n > _MAX_POINTS_PER_CLASS:
            idx = np.linspace(0, n - 1, _MAX_POINTS_PER_CLASS).astype(int)
            points = points[idx]
        pts = [[round(float(x), 4), round(float(y), 4)]
               for x, y in points]
        out.append({
            "label": "恶意" if label == 1 else "良性",
            "color": colors.get(label, "#888888"),
            "points": pts,
        })
    return out


def build_viz(embedding):
    """一次性组装 /predict 的 viz 字段；无 KB 时返回 None。"""
    point = project_sample(embedding)
    clusters = get_clusters()
    if point is None or not clusters:
        return None
    return {"point": point, "clusters": clusters,
            "dim_reduction": "PCA-2D"}
