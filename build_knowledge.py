"""
特征知识库构建 — 从 AES-256 加密封存包（G 盘）内存读取训练样本，
用 CNN 嵌入(256维)构建"经验记忆"知识库，落盘到 checkpoints/。

前提：已运行 seal_samples.py 封存明文；封存密码在 monitor_data/seal_passphrase.txt。
不把恶意明文写回磁盘，全程内存处理。

用法:
  F:\\Python314\\python.exe build_knowledge.py [--seal-dir G:\\御天防护型AI\\样本封存] [--max-per-class N]
"""
import os
import sys
import glob
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import CHECKPOINT_DIR, OOD_CONF_THRESHOLD, OOD_MAHAL_THRESHOLD
from models import knowledge as KB

DEFAULT_SEAL_DIR = r"G:\御天防护型AI\样本封存"
PASSFILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "monitor_data", "seal_passphrase.txt")


def _latest_zip(seal_dir, prefix):
    """找到目录下最新的 prefix*.zip"""
    try:
        cands = glob.glob(os.path.join(seal_dir, prefix + "_*.zip"))
        if not cands:
            return None
        return max(cands, key=os.path.getmtime)
    except Exception:
        return None


def _iter_zip_bytes(zip_path, password, label, limit):
    """逐个读出封存包内样本 bytes。返回 (bytes 列表, 文件名列表)"""
    import pyzipper
    raw_list, name_list = [], []
    with pyzipper.AESZipFile(zip_path, "r") as zf:
        zf.setpassword(password.encode())
        for info in zf.infolist():
            if info.is_dir():
                continue
            data = zf.read(info.filename)
            raw_list.append(data)
            name_list.append(os.path.basename(info.filename))
            if limit and len(raw_list) >= limit:
                break
    return raw_list, name_list


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seal-dir", default=DEFAULT_SEAL_DIR)
    ap.add_argument("--max-per-class", type=int, default=0, help="每类最多样本数(0=全部)")
    args = ap.parse_args()

    if not os.path.isfile(PASSFILE):
        sys.exit("未找到封存密码: " + PASSFILE)
    password = open(PASSFILE, encoding="utf-8").read().strip()

    # 加载模型
    import torch
    from config import MODEL_PATH, IMG_SIZE
    from data.binary_to_image import array_to_square_image
    from models.cnn import GuardianCNN
    from models.ood import load_stats
    cp = torch.load(MODEL_PATH, map_location="cpu", weights_only=False)
    img_size = cp.get("img_size", IMG_SIZE)
    model = GuardianCNN(input_size=img_size)
    model.load_state_dict(cp["model_state_dict"])
    model.eval()
    print("[KB] 模型已加载。img_size=%d" % img_size)

    features = {0: [], 1: []}
    meta = {0: [], 1: []}
    plan = [("malware", 1, _latest_zip(args.seal_dir, "malware")),
            ("benign", 0, _latest_zip(args.seal_dir, "benign"))]

    total = 0
    for tag, label, zip_path in plan:
        if not zip_path:
            print("[KB] 未找到 %s 封存包，跳过。" % tag)
            continue
        raw_list, names = _iter_zip_bytes(zip_path, password, tag, args.max_per_class)
        print("[KB] %s: %d 个样本 <- %s" % (tag, len(raw_list), os.path.basename(zip_path)))
        with torch.no_grad():
            for raw, name in zip(raw_list, names):
                arr = bytes(raw)
                img = array_to_square_image(np_from(arr), img_size)
                t = torch.from_numpy(img).float().unsqueeze(0).unsqueeze(0) / 255.0
                emb = model.embed(t).squeeze(0).numpy()
                features[label].append(emb)
                meta[label].append({
                    "file": name,
                    "sha": KB.sha256_bytes(raw),
                    "label_name": "恶意" if label == 1 else "良性",
                })
                total += 1

    if not features[0] or not features[1]:
        sys.exit("至少需要恶意与良性各若干样本，才能构建配对知识库。")

    feat_mat = {lbl: __import__("numpy").asarray(f, dtype="float32") for lbl, f in features.items()}
    KB.save_knowledge(feat_mat, meta)
    print("[KB] 知识库写入完成:")
    print("     恶意样本: %d, 良性样本: %d" % (len(features[1]), len(features[0])))
    print("     特征: %s" % ", ".join("%s%sx%d" % (k, f.shape[0], f.shape[1]) for k, f in feat_mat.items()))
    print("     文件: %s" % KB.KB_FEATURES)
    print("     元数据: %s" % KB.KB_META)


def np_from(arr):
    import numpy as np
    return np.frombuffer(arr, dtype=np.uint8)


if __name__ == "__main__":
    main()