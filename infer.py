"""
推理入口 — 用训练好的模型检测文件
用法:
  python infer.py <文件路径>                 # 检测单个文件
  python infer.py <目录路径>                 # 检测目录下所有文件
  python infer.py <文件路径> --threshold 0.8 # 自定义恶意判定阈值
  python infer.py <目录路径> --device cpu    # 指定设备 cpu / cuda
  python infer.py <目录路径> --recursive     # 递归扫描子目录
  python infer.py <目录路径> --no_batch      # 关闭目录批推理（逐文件）
"""
import os
import sys
import argparse
import torch
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import (IMG_SIZE, MODEL_PATH, VALID_EXTENSIONS,
                    MAX_FILE_SIZE, MIN_FILE_SIZE, TORCH_THREADS,
                    OOD_STATS_FILE, OOD_MAHAL_THRESHOLD, OOD_CONF_THRESHOLD)
from data.binary_to_image import file_to_image_tensor
from models.cnn import GuardianCNN
from models.ood import load_stats, classify


def load_model(model_path=MODEL_PATH, img_size=IMG_SIZE, device="cpu"):
    """加载训练好的模型，并尝试加载 OOD 统计"""
    if not os.path.isfile(model_path):
        print(f"[错误] 模型文件不存在: {model_path}")
        print("请先运行 train.py 训练模型")
        sys.exit(1)

    checkpoint = torch.load(model_path, map_location=device, weights_only=False)
    img_size = checkpoint.get("img_size", img_size)

    model = GuardianCNN(input_size=img_size)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.to(device)
    model.eval()

    ood_stats = load_stats(OOD_STATS_FILE)
    print(f"[模型] 已加载 {model_path}")
    print(f"[模型] epoch={checkpoint['epoch']}  val_acc={checkpoint['val_acc']*100:.2f}%")
    print(f"[OOD] 未知检测统计: {'已加载' if ood_stats else '未加载(仅用置信度判定)'}")
    return model, img_size, ood_stats


def file_to_tensor(file_path, img_size):
    """返回待检测文件的归一化 tensor，或 (错误信息, None)"""
    if not os.path.isfile(file_path):
        return "错误(不存在)", None
    size = os.path.getsize(file_path)
    if size < MIN_FILE_SIZE or size > MAX_FILE_SIZE:
        return "跳过(大小不符)", None
    tensor = file_to_image_tensor(file_path, img_size)
    if tensor is None:
        return "错误(转换失败)", None
    return None, tensor


def predict_tensor(model, tensor, img_size, device="cpu", ood_stats=None,
                   mahal_threshold=OOD_MAHAL_THRESHOLD, conf_threshold=OOD_CONF_THRESHOLD,
                   threshold=0.5):
    """
    对单个归一化 tensor 预测，融合 softmax 概率 + OOD 马氏距离。
    返回: (label_str, confidence, {"benign": p0, "malware": p1})
    label 可能为 良性 / 恶意 / 未知。
    """
    tensor = tensor.unsqueeze(0).to(device)
    with torch.no_grad():
        logits = model(tensor)
        probs = torch.softmax(logits, dim=1)
        emb = model.embed(tensor).cpu().numpy()[0] if ood_stats else None

    benign_prob = probs[0][0].item()
    malware_prob = probs[0][1].item()
    probs_dict = {"benign": benign_prob, "malware": malware_prob}

    label, _ = classify(
        [benign_prob, malware_prob], emb=emb, stats=ood_stats,
        mahal_threshold=mahal_threshold, conf_threshold=conf_threshold,
    )
    if label == "未知":
        confidence = max(benign_prob, malware_prob)
    elif label == "恶意":
        confidence = malware_prob
    else:
        confidence = benign_prob
    return label, confidence, probs_dict


def predict_file(model, file_path, img_size, device="cpu", threshold=0.5,
                 ood_stats=None, mahal_threshold=OOD_MAHAL_THRESHOLD,
                 conf_threshold=OOD_CONF_THRESHOLD):
    """
    预测单个文件
    返回: (label_str, confidence, probabilities)
    """
    err, tensor = file_to_tensor(file_path, img_size)
    if err is not None:
        return err, 0.0, {"benign": 0, "malware": 0}
    return predict_tensor(model, tensor, img_size, device, ood_stats,
                          mahal_threshold, conf_threshold, threshold)


def predict_batch(model, tensors, device="cpu"):
    """对一批 tensor 做推理，返回每条的 (malware_prob, benign_prob)"""
    if not tensors:
        return []
    batch = torch.stack(tensors).to(device)
    with torch.no_grad():
        probs = torch.softmax(model(batch), dim=1)
    return [(p[1].item(), p[0].item()) for p in probs]


def scan_files(target, recursive=False):
    """收集目录下所有可检测文件（可选递归）"""
    files = []
    if recursive:
        for root, _, names in os.walk(target):
            for name in names:
                fp = os.path.join(root, name)
                if os.path.isfile(fp):
                    _, ext = os.path.splitext(name)
                    if ext.lower() in VALID_EXTENSIONS:
                        files.append(fp)
    else:
        for name in os.listdir(target):
            fp = os.path.join(target, name)
            if not os.path.isfile(fp):
                continue
            _, ext = os.path.splitext(name)
            if ext.lower() in VALID_EXTENSIONS:
                files.append(fp)
    return files


def main():
    parser = argparse.ArgumentParser(description="防护型 AI 推理")
    parser.add_argument("target", help="文件或目录路径")
    parser.add_argument("--model", default=MODEL_PATH, help="模型路径")
    parser.add_argument("--threshold", type=float, default=0.5,
                        help="恶意判定阈值 (默认 0.5)")
    parser.add_argument("--device", choices=["cpu", "cuda"], default="auto",
                        help="推理设备 (默认自动: 有 GPU 用 cuda)")
    parser.add_argument("--recursive", action="store_true", help="递归扫描子目录")
    parser.add_argument("--no_batch", action="store_true", help="目录检测改为逐文件推理")
    args = parser.parse_args()

    # 设备：默认自动
    device = (torch.device("cuda" if torch.cuda.is_available() else "cpu")
              if args.device == "auto" else torch.device(args.device))
    # CPU 推理时可指定线程数以提速
    if device.type == "cpu" and TORCH_THREADS > 0:
        torch.set_num_threads(TORCH_THREADS)

    print("=" * 60)
    print("  御天防护型 AI — 推理检测")
    print("=" * 60)
    print(f"[设备] {device}  阈值={args.threshold}")

    model, img_size, ood_stats = load_model(args.model, IMG_SIZE, device)

    target = args.target
    if os.path.isfile(target):
        # ---------- 单文件 ----------
        label, conf, probs = predict_file(model, target, img_size, device, args.threshold,
                                          ood_stats)
        print(f"\n文件: {target}")
        print(f"大小: {os.path.getsize(target):,} bytes")
        print(f"判定: {label}  (置信度 {conf*100:.1f}%)")
        print(f"概率: 良性={probs['benign']*100:.1f}%  恶意={probs['malware']*100:.1f}%")
        return

    if not os.path.isdir(target):
        print(f"[错误] 路径不存在: {target}")
        sys.exit(1)

    # ---------- 目录扫描 ----------
    files = scan_files(target, args.recursive)
    print(f"\n扫描目录: {target}  (递归={'是' if args.recursive else '否'})")
    print(f"发现 {len(files)} 个可检测文件\n")
    print(f"{'文件名':<50} {'判定':<8} {'置信度':<10} {'恶意概率'}")
    print("-" * 80)

    results = {"malware": 0, "benign": 0, "unknown": 0, "skip": 0, "error": 0}

    if args.no_batch:
        # 逐文件推理（兼容性/低内存模式）
        for fp in tqdm(files, desc="检测", unit="个", ncols=90):
            label, conf, probs = predict_file(model, fp, img_size, device, args.threshold,
                                              ood_stats)
            if label == "恶意":
                results["malware"] += 1
            elif label == "良性":
                results["benign"] += 1
            elif label == "未知":
                results["unknown"] += 1
            elif "跳过" in label:
                results["skip"] += 1
            else:
                results["error"] += 1
            print(f"{os.path.basename(fp):<50} {label:<8} {conf*100:>7.1f}%   "
                  f"{probs['malware']*100:.1f}%")
    else:
        # 批推理：先转换成 tensor，再分批送入模型，GPU/CPU 上都更快
        valid = []      # (file_path, tensor)
        for fp in tqdm(files, desc="转换", unit="个", ncols=90):
            err, tensor = file_to_tensor(fp, img_size)
            if err is not None:
                # 累计跳过/错误，但稍后打印
                valid.append((fp, err, None))
            else:
                valid.append((fp, None, tensor))

        batch_size = 32
        for start in tqdm(range(0, len(valid), batch_size), desc="检测", unit="批", ncols=90):
            chunk = valid[start:start + batch_size]
            items = [(fp, err, t) for fp, err, t in chunk]
            # 提取本批可推理的 tensor
            batch_tensors = [(i, t) for i, (_, err, t) in enumerate(items) if err is None and t is not None]
            batch_results = {}
            if batch_tensors:
                # 构造小批量输入，一次前向得到 logits(用于概率) 与嵌入(用于 OOD)
                ts = torch.stack([t for _, t in batch_tensors]).to(device)
                with torch.no_grad():
                    logits = model(ts)
                    probs = torch.softmax(logits, dim=1).cpu().numpy()
                    embs = model.embed(ts).cpu().numpy()
                for (i, _), p, e in zip(batch_tensors, probs, embs):
                    label, _ = classify(list(p), emb=(e if ood_stats else None),
                                        stats=ood_stats,
                                        mahal_threshold=OOD_MAHAL_THRESHOLD,
                                        conf_threshold=OOD_CONF_THRESHOLD)
                    conf = max(p) if label == "未知" else (p[1] if label == "恶意" else p[0])
                    batch_results[i] = (label, conf, list(p))
            # 逐条归类输出
            for i, (fp, err, _) in enumerate(items):
                name = os.path.basename(fp)
                if err is not None:
                    label = err
                    results["skip" if "跳过" in err else "error"] += 1
                    print(f"{name:<50} {label:<8}")
                else:
                    label, conf, p = batch_results[i]
                    if label == "恶意":
                        results["malware"] += 1
                    elif label == "良性":
                        results["benign"] += 1
                    else:
                        results["unknown"] += 1
                    print(f"{name:<50} {label:<8} {conf*100:>7.1f}%   {p[1]*100:.1f}%")

    print("-" * 80)
    print(f"\n汇总: 恶意={results['malware']}  良性={results['benign']}  "
          f"未知={results['unknown']}  跳过={results['skip']}  错误={results['error']}")


if __name__ == "__main__":
    main()