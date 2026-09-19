"""
二进制 → 灰度图转换器
将 PE 文件的原始字节映射为二维灰度图像
"""
import os
import numpy as np
from PIL import Image

# 允许直接 import config
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import IMG_SIZE


def bytes_to_grayscale_array(raw_bytes):
    """
    将原始字节转为 numpy uint8 数组（0-255 灰度值）
    """
    return np.frombuffer(raw_bytes, dtype=np.uint8)


def array_to_square_image(arr, target_size=IMG_SIZE):
    """
    将一维字节数组转为正方形灰度图并 resize

    策略:
    1. 计算最接近的正方形边长
    2. 填充/截断到完整正方形
    3. PIL resize 到 target_size x target_size
    """
    total = len(arr)
    if total == 0:
        return np.zeros((target_size, target_size), dtype=np.uint8)

    # 计算正方形边长（向上取整）
    side = int(np.ceil(np.sqrt(total)))

    # 填充到完整正方形
    padded = np.zeros(side * side, dtype=np.uint8)
    padded[:total] = arr

    # reshape 为 2D
    img_2d = padded.reshape((side, side))

    # 如果原图比目标大，用 PIL 缩放
    if side != target_size:
        pil_img = Image.fromarray(img_2d, mode="L")
        pil_img = pil_img.resize((target_size, target_size), Image.BILINEAR)
        img_2d = np.array(pil_img, dtype=np.uint8)

    return img_2d


def file_to_image(file_path, target_size=IMG_SIZE):
    """
    读取二进制文件 → 返回灰度图 numpy 数组 (target_size, target_size)

    返回: np.ndarray shape=(H, W) dtype=uint8, 或 None(失败时)
    """
    try:
        with open(file_path, "rb") as f:
            raw = f.read()
        arr = bytes_to_grayscale_array(raw)
        img = array_to_square_image(arr, target_size)
        return img
    except Exception as e:
        print(f"[binary_to_image] 转换失败 {file_path}: {e}")
        return None


def file_to_image_tensor(file_path, target_size=IMG_SIZE):
    """
    读取二进制文件 → 返回 PyTorch tensor (1, H, W) float32 归一化到 [0,1]
    """
    import torch

    img = file_to_image(file_path, target_size)
    if img is None:
        return None

    # 归一化到 [0, 1] 并添加通道维度
    tensor = torch.from_numpy(img).float() / 255.0
    tensor = tensor.unsqueeze(0)  # (1, H, W)
    return tensor


def save_image_cache(file_path, cache_dir, target_size=IMG_SIZE):
    """将文件的灰度图保存为 .npy 缓存，加速后续训练"""
    img = file_to_image(file_path, target_size)
    if img is None:
        return False

    cache_name = os.path.splitext(os.path.basename(file_path))[0] + ".npy"
    cache_path = os.path.join(cache_dir, cache_name)
    np.save(cache_path, img)
    return True


if __name__ == "__main__":
    # 测试：对单个文件生成灰度图并保存 PNG 预览
    import sys

    if len(sys.argv) < 2:
        print("用法: python binary_to_image.py <文件路径> [输出.png]")
        sys.exit(1)

    fp = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "preview.png"

    img = file_to_image(fp, IMG_SIZE)
    if img is not None:
        Image.fromarray(img, mode="L").save(out)
        print(f"灰度图已保存: {out}  尺寸: {img.shape}")
    else:
        print("转换失败")
