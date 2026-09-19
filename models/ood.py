"""
OOD 未知样本检测 — 在 CNN 嵌入特征(256维)上对已知两类拟合高斯统计，
用 Mahalanobis 距离 + softmax 置信度识别陌生/看不清样本，判为"未知"。

与四态融合配合：CNN 不确定或离已知类簇太远时，不硬判 良性/恶意，
而是交给"未知"与监控层兜底。
"""
import os
import sys
import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (OOD_STATS_FILE, OOD_EMBED_DIM, OOD_COV_REG)


def collect_embeddings(model, loader, device="cpu"):
    """
    对数据集跑一遍，收集每类样本的嵌入特征。
    返回: {0: (N0, D), 1: (N1, D)}  类别 → 嵌入矩阵
    """
    model.eval()
    per_class = {0: [], 1: []}
    with torch.no_grad():
        for images, labels in loader:
            images = images.to(device)
            emb = model.embed(images).cpu().numpy()
            for e, l in zip(emb, labels.numpy()):
                per_class[int(l)].append(np.asarray(e).reshape(-1))
    return {k: np.stack(v) if v else np.zeros((0, OOD_EMBED_DIM))
            for k, v in per_class.items()}


def _fit_gaussian(emb_matrix):
    """对一类嵌入拟合(均值, 协方差)，协方差加正则保证可逆。返回 (mean, inv_cov)。"""
    if emb_matrix.shape[0] == 0:
        raise ValueError("该类无样本，无法拟合高斯统计")
    mean = emb_matrix.mean(axis=0)
    center = emb_matrix - mean
    n = emb_matrix.shape[0]
    cov = (center.T @ center) / max(n - 1, 1)
    cov += OOD_COV_REG * np.eye(OOD_EMBED_DIM)
    inv_cov = np.linalg.inv(cov)
    return mean, inv_cov


def fit_ood_stats(model, loader, device="cpu"):
    """
    拟合训练集上的类高斯统计 → 返回可持久化的 dict，并可落盘到 OOD_STATS_FILE。
    """
    per_class = collect_embeddings(model, loader, device)
    stats = {"means": {}, "inv_covs": {}, "counts": {}}
    for label, mat in per_class.items():
        if mat.shape[0] == 0:
            continue
        mean, inv = _fit_gaussian(mat)
        stats["means"][label] = mean
        stats["inv_covs"][label] = inv
        stats["counts"][label] = mat.shape[0]
    return stats


def save_stats(stats, path=OOD_STATS_FILE):
    """把类高斯统计落盘为 .npz，供推理加载。"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    arrays = {}
    for label in stats["means"]:
        arrays[f"mean_{label}"] = np.asarray(stats["means"][label])
        arrays[f"inv_{label}"] = np.asarray(stats["inv_covs"][label])
        arrays[f"count_{label}"] = np.array([stats["counts"][label]])
    np.savez(path, **arrays)
    return path


def load_stats(path=OOD_STATS_FILE):
    """加载 .npz 中的类高斯统计；文件缺失返回 None。"""
    if not os.path.isfile(path):
        return None
    z = np.load(path)
    stats = {"means": {}, "inv_covs": {}, "counts": {}}
    for key in z.files:
        kind, label = key.split("_", 1)
        label = int(label)
        if kind == "mean":
            stats["means"][label] = z[key]
        elif kind == "inv":
            stats["inv_covs"][label] = z[key]
        elif kind == "count":
            stats["counts"][label] = int(z[key][0])
    return stats if stats["means"] else None


def mahalanobis_vector(x, mean, inv_cov):
    """单个嵌入向量到某类的高斯马氏距离。"""
    d = np.asarray(x) - np.asarray(mean)
    return float(np.sqrt(max(d @ inv_cov @ d, 0.0)))


def min_mahalanobis(x, stats):
    """到最近已知类中心的马氏距离。stats 为 load_stats 的返回值。"""
    if not stats:
        return 0.0
    return min(mahalanobis_vector(x, stats["means"][c], stats["inv_covs"][c])
               for c in stats["means"])


def classify(probs, emb=None, stats=None, mahal_threshold=float("inf"),
             conf_threshold=0.0):
    """
    结合 CNN softmax 概率 + 马氏距离 判最终静态标签。
    返回: (label_str, is_unknown)
      label_str: 良性 / 恶意 / 未知
    判定优先级: 置信度过低→未知；离已知类簇过远→未知。
    """
    probs = np.asarray(probs, dtype=float)
    top_conf = float(probs.max())
    pred = int(probs.argmax())

    # 1) 置信度过低 → 无法看清
    if top_conf < conf_threshold:
        return "未知", True

    # 2) 有 OOD 统计且离已知类簇过远 → 陌生
    if emb is not None and stats is not None and mahal_threshold != float("inf"):
        dist = min_mahalanobis(emb, stats)
        if dist > mahal_threshold:
            return "未知", True

    return ("恶意" if pred == 1 else "良性"), False


if __name__ == "__main__":
    # 冒烟测试：构造随机数据验证高斯拟合并返回可读信息
    rng = np.random.default_rng(0)
    m0 = _fit_gaussian(rng.normal(0, 0.5, (200, OOD_EMBED_DIM)))
    print("良性类 mean 形状:", m0[0].shape, "| inv_cov 形状:", m0[1].shape)
    print("就近马氏距离(类内样本):",
          min(mahalanobis_vector(rng.normal(0, 0.5, OOD_EMBED_DIM), *m0)
              for _ in range(3)))
    print("OOD 模块冒烟测试通过")