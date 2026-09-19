"""
训练入口 — 二进制灰度图 CNN 恶意软件分类器
用法:
  python train.py                    # 默认参数训练
  python train.py --epochs 50        # 指定 epoch
  python train.py --img_size 128     # 128x128 图像
  python train.py --metric acc       # 按准确率而非 F1 保存最优模型
"""
import os
import sys
import time
import random
import argparse
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import (
    IMG_SIZE, BATCH_SIZE, LEARNING_RATE, EPOCHS, VAL_RATIO, TEST_RATIO,
    BEST_METRIC, LR_PATIENCE, LR_FACTOR, EARLY_STOP_PATIENCE, SEED,
    MODEL_PATH, CHECKPOINT_DIR, OOD_MAHAL_THRESHOLD,
)
from data.dataset import build_dataloaders
from models.cnn import GuardianCNN, count_parameters
from models.ood import fit_ood_stats, save_stats


def set_seed(seed=SEED):
    """固定随机种子，保证训练可复现"""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def train_one_epoch(model, loader, criterion, optimizer, device):
    """训练一个 epoch"""
    model.train()
    total_loss = 0.0
    correct = 0
    total = 0

    for batch_idx, (images, labels) in enumerate(tqdm(loader, desc="  训练中", leave=False,
                                                      unit="批", ncols=90)):
        images, labels = images.to(device), labels.to(device)

        optimizer.zero_grad()
        outputs = model(images)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()

        total_loss += loss.item() * images.size(0)
        _, predicted = outputs.max(1)
        correct += predicted.eq(labels).sum().item()
        total += labels.size(0)

    avg_loss = total_loss / total
    accuracy = correct / total
    return avg_loss, accuracy


def validate(model, loader, criterion, device):
    """验证"""
    model.eval()
    total_loss = 0.0
    correct = 0
    total = 0

    # 详细统计（用于计算 precision / recall / F1）
    tp = 0  # 恶意正确判定为恶意
    fp = 0  # 良性误判为恶意
    tn = 0  # 良性正确判定为良性
    fn = 0  # 恶意漏判为良性

    with torch.no_grad():
        for images, labels in loader:
            images, labels = images.to(device), labels.to(device)
            outputs = model(images)
            loss = criterion(outputs, labels)

            total_loss += loss.item() * images.size(0)
            _, predicted = outputs.max(1)
            correct += predicted.eq(labels).sum().item()
            total += labels.size(0)

            # 混淆矩阵
            for p, l in zip(predicted, labels):
                if l == 1 and p == 1:
                    tp += 1
                elif l == 0 and p == 1:
                    fp += 1
                elif l == 0 and p == 0:
                    tn += 1
                elif l == 1 and p == 0:
                    fn += 1

    avg_loss = total_loss / total
    accuracy = correct / total

    # precision / recall / F1（恶意类为正类）
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return avg_loss, accuracy, {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
    }


def main():
    parser = argparse.ArgumentParser(description="训练防护型 AI")
    parser.add_argument("--epochs", type=int, default=EPOCHS, help=f"训练轮数 (默认 {EPOCHS})")
    parser.add_argument("--batch_size", type=int, default=BATCH_SIZE, help=f"批大小 (默认 {BATCH_SIZE})")
    parser.add_argument("--lr", type=float, default=LEARNING_RATE, help=f"学习率 (默认 {LEARNING_RATE})")
    parser.add_argument("--img_size", type=int, default=IMG_SIZE, help=f"图像尺寸 (默认 {IMG_SIZE})")
    parser.add_argument("--metric", choices=["f1", "acc"], default=BEST_METRIC,
                        help=f"最优模型保存依据 (默认 {BEST_METRIC})")
    parser.add_argument("--seed", type=int, default=SEED, help=f"随机种子 (默认 {SEED})")
    parser.add_argument("--no_test", action="store_true", help="不划分/不评估独立测试集")
    parser.add_argument("--no_cache", action="store_true", help="禁用图像缓存")
    args = parser.parse_args()

    set_seed(args.seed)
    test_ratio = 0.0 if args.no_test else TEST_RATIO

    print("=" * 60)
    print("  御天防护型 AI — 训练启动")
    print("  二进制 → 灰度图 → CNN 二分类")
    print("=" * 60)

    # 设备
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n[设备] {device}")
    if device.type == "cpu":
        print("[设备] ⚠ CPU 模式，训练较慢，请耐心等待")

    # 数据
    print(f"\n[数据] 加载数据集 (img_size={args.img_size}, batch={args.batch_size}, "
          f"test_ratio={test_ratio})...")
    train_loader, val_loader, test_loader, info = build_dataloaders(
        img_size=args.img_size,
        batch_size=args.batch_size,
        val_ratio=VAL_RATIO,
        test_ratio=test_ratio,
        use_cache=not args.no_cache,
    )
    print(f"[数据] 训练集={info['train']}  验证集={info['val']}  "
          f"测试集={info['test']}  (恶意={info['malware']} 良性={info['benign']})")

    # 模型
    model = GuardianCNN(input_size=args.img_size).to(device)
    print(f"\n[模型] GuardianCNN  参数量={count_parameters(model):,}")

    # 类别平衡：按各类样本占比反比赋权，缓解样本不均
    n_mal = max(info['malware'], 1)
    n_ben = max(info['benign'], 1)
    class_weights = torch.tensor([n_mal / (n_mal + n_ben), n_ben / (n_mal + n_ben)],
                                 dtype=torch.float32).to(device)
    print(f"[数据] 类别权重: 良性={class_weights[0]:.3f} 恶意={class_weights[1]:.3f}")

    # 损失 & 优化器
    criterion = nn.CrossEntropyLoss(weight=class_weights)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)
    # 学习率调度：验证指标不再下降时衰减 lr
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="max", patience=LR_PATIENCE, factor=LR_FACTOR
    )

    # 训练循环
    print(f"\n[训练] epochs={args.epochs}  lr={args.lr}  batch={args.batch_size}  "
          f"metric={args.metric}")
    print("-" * 60)

    best_score = 0.0
    best_metrics = None
    no_improve_epochs = 0  # 早停计数

    for epoch in range(1, args.epochs + 1):
        t0 = time.time()
        print(f"\nEpoch {epoch}/{args.epochs}")

        train_loss, train_acc = train_one_epoch(model, train_loader, criterion, optimizer, device)
        val_loss, val_acc, metrics = validate(model, val_loader, criterion, device)

        # 当前学习率
        cur_lr = optimizer.param_groups[0]["lr"]
        scheduler.step(val_acc)  # 依据验证准确率调度

        elapsed = time.time() - t0
        print(f"  训练  loss={train_loss:.4f}  acc={train_acc*100:.2f}%")
        print(f"  验证  loss={val_loss:.4f}  acc={val_acc*100:.2f}%")
        print(f"  指标  precision={metrics['precision']:.4f}  "
              f"recall={metrics['recall']:.4f}  F1={metrics['f1']:.4f}  lr={cur_lr:.2e}")
        print(f"  混淆  TP={metrics['tp']}  FP={metrics['fp']}  "
              f"TN={metrics['tn']}  FN={metrics['fn']}")
        print(f"  耗时  {elapsed:.1f}s")

        # 最优模型依据（恶意检测优先看 F1）
        score = metrics["f1"] if args.metric == "f1" else val_acc

        if score > best_score:
            best_score = score
            best_metrics = {**metrics, "acc": val_acc, "loss": val_loss}
            no_improve_epochs = 0
            os.makedirs(CHECKPOINT_DIR, exist_ok=True)
            torch.save({
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "val_acc": val_acc,
                "val_f1": metrics["f1"],
                "metric": args.metric,
                "img_size": args.img_size,
            }, MODEL_PATH)
            print(f"  ✅ 最优模型已保存: {MODEL_PATH} "
                  f"({args.metric}={score:.4f}, val_acc={val_acc*100:.2f}%)")
        else:
            no_improve_epochs += 1
            if EARLY_STOP_PATIENCE > 0 and no_improve_epochs >= EARLY_STOP_PATIENCE:
                print(f"\n⏹ 验证指标 {no_improve_epochs} 个 epoch 未提升，提前停止训练")
                break

    # 训练结束
    print("\n" + "=" * 60)
    if best_metrics:
        print(f"  训练完成！")
        print(f"  最优 {args.metric}:   {best_score:.4f}")
        print(f"  最优验证准确率:      {best_metrics['acc']*100:.2f}%")
        print(f"  最优 F1 分数:        {best_metrics['f1']:.4f}")
        print(f"  模型保存位置:        {MODEL_PATH}")
    print("=" * 60)

    # 在独立测试集上做最终评估（使用保存的最优权重）
    if test_loader is not None:
        print(f"\n[测试] 在独立测试集 ({info['test']} 样本) 上做最终评估...")
        checkpoint = torch.load(MODEL_PATH, map_location=device, weights_only=False)
        model.load_state_dict(checkpoint["model_state_dict"])
        test_loss, test_acc, test_metrics = validate(model, test_loader, criterion, device)
        print(f"  测试  loss={test_loss:.4f}  acc={test_acc*100:.2f}%")
        print(f"  测试  precision={test_metrics['precision']:.4f}  "
              f"recall={test_metrics['recall']:.4f}  F1={test_metrics['f1']:.4f}")
        print(f"  测试  混淆  TP={test_metrics['tp']}  FP={test_metrics['fp']}  "
              f"TN={test_metrics['tn']}  FN={test_metrics['fn']}")

    # 拟合并落盘 OOD 类高斯统计（用最优权重在训练集上收集嵌入）
    print("\n[OOD] 在训练集上拟合嵌入特征统计，生成未知样本判定基准...")
    model.load_state_dict(torch.load(MODEL_PATH, map_location=device,
                                     weights_only=False)["model_state_dict"])
    stats = fit_ood_stats(model, train_loader, device)
    save_stats(stats)
    print(f"[OOD] 已保存类高斯统计: {os.path.join(CHECKPOINT_DIR, 'ood_stats.npz')}")
    print(f"[OOD] Mahalanobis 距离阈值: {OOD_MAHAL_THRESHOLD}")


if __name__ == "__main__":
    main()
