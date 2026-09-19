"""
PyTorch Dataset — 加载恶意/良性二进制样本并转为灰度图
"""
import os
import sys
import numpy as np
import torch
from torch.utils.data import Dataset, DataLoader

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    MALWARE_DIR, BENIGN_DIR, IMAGE_CACHE_DIR, IMG_SIZE, IMG_CHANNELS,
    BATCH_SIZE, VAL_RATIO, TEST_RATIO, MAX_SAMPLES_PER_CLASS,
    VALID_EXTENSIONS, MAX_FILE_SIZE, MIN_FILE_SIZE,
)
from data.binary_to_image import file_to_image


def scan_samples(sample_dir, label, max_count=0):
    """
    扫描目录下的有效样本文件
    返回: [(file_path, label), ...]
    """
    samples = []
    if not os.path.isdir(sample_dir):
        return samples

    for name in os.listdir(sample_dir):
        fp = os.path.join(sample_dir, name)
        if not os.path.isfile(fp):
            continue

        _, ext = os.path.splitext(name)
        if ext.lower() not in VALID_EXTENSIONS:
            continue

        size = os.path.getsize(fp)
        if size < MIN_FILE_SIZE or size > MAX_FILE_SIZE:
            continue

        samples.append((fp, label))
        if max_count and len(samples) >= max_count:
            break

    return samples


class MalwareImageDataset(Dataset):
    """
    恶意软件灰度图数据集
    label: 0 = 良性(benign), 1 = 恶意(malware)
    """

    def __init__(self, file_list, img_size=IMG_SIZE, use_cache=True):
        self.file_list = file_list
        self.img_size = img_size
        self.use_cache = use_cache

        os.makedirs(IMAGE_CACHE_DIR, exist_ok=True)

    def __len__(self):
        return len(self.file_list)

    def __getitem__(self, idx):
        file_path, label = self.file_list[idx]

        # 尝试从缓存加载
        if self.use_cache:
            cache_name = os.path.splitext(os.path.basename(file_path))[0] + ".npy"
            cache_path = os.path.join(IMAGE_CACHE_DIR, cache_name)
            if os.path.exists(cache_path):
                try:
                    img = np.load(cache_path)
                except Exception:
                    img = file_to_image(file_path, self.img_size)
            else:
                img = file_to_image(file_path, self.img_size)
                if img is not None:
                    np.save(cache_path, img)
        else:
            img = file_to_image(file_path, self.img_size)

        # 转换失败时返回全黑图
        if img is None:
            img = np.zeros((self.img_size, self.img_size), dtype=np.uint8)

        # 转 tensor: (1, H, W) float32 [0,1]
        tensor = torch.from_numpy(img).float() / 255.0
        tensor = tensor.unsqueeze(0)  # 添加通道维度

        return tensor, torch.tensor(label, dtype=torch.long)


def build_dataloaders(img_size=IMG_SIZE, batch_size=BATCH_SIZE, val_ratio=VAL_RATIO,
                      test_ratio=TEST_RATIO, use_cache=True):
    """
    构建训练/验证/测试 DataLoader

    返回: (train_loader, val_loader, test_loader, dataset_info)
    test_loader 在 test_ratio<=0 时为 None（训练期间使用）
    """
    max_per = MAX_SAMPLES_PER_CLASS if MAX_SAMPLES_PER_CLASS > 0 else 0

    malware_samples = scan_samples(MALWARE_DIR, label=1, max_count=max_per)
    benign_samples = scan_samples(BENIGN_DIR, label=0, max_count=max_per)

    all_samples = malware_samples + benign_samples

    print(f"[dataset] 恶意样本: {len(malware_samples)}")
    print(f"[dataset] 良性样本: {len(benign_samples)}")
    print(f"[dataset] 总计: {len(all_samples)}")

    if len(all_samples) == 0:
        raise RuntimeError("没有可用样本！请先运行 downloader.py 下载样本")

    if len(malware_samples) == 0 or len(benign_samples) == 0:
        raise RuntimeError("恶意或良性样本为空！需要两类样本才能训练分类器")

    # 打乱（可复现由外部设置全局种子控制）
    np.random.shuffle(all_samples)

    # 1) 先留出独立测试集
    test_list = []
    if test_ratio > 0:
        test_count = max(1, int(len(all_samples) * test_ratio))
        test_list = all_samples[:test_count]
        all_samples = all_samples[test_count:]

    # 2) 其余按 val_ratio 划分训练/验证
    val_count = max(1, int(len(all_samples) * val_ratio))
    val_list = all_samples[:val_count]
    train_list = all_samples[val_count:]

    train_ds = MalwareImageDataset(train_list, img_size, use_cache)
    val_ds = MalwareImageDataset(val_list, img_size, use_cache)
    test_ds = MalwareImageDataset(test_list, img_size, use_cache) if test_list else None

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, num_workers=0)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False, num_workers=0)
    test_loader = (DataLoader(test_ds, batch_size=batch_size, shuffle=False, num_workers=0)
                   if test_ds else None)

    info = {
        "total": len(all_samples) + len(test_list),
        "train": len(train_list),
        "val": len(val_list),
        "test": len(test_list),
        "malware": len(malware_samples),
        "benign": len(benign_samples),
    }

    return train_loader, val_loader, test_loader, info
