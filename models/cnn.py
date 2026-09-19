"""
轻量 CNN 模型 — 二进制灰度图恶意软件分类
4 层卷积 + 2 层全连接，约 200K 参数，CPU 友好
"""
import torch
import torch.nn as nn
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import IMG_SIZE, IMG_CHANNELS, DROPOUT


class GuardianCNN(nn.Module):
    """
    输入: (B, 1, 64, 64) 灰度图
    输出: (B, 2)  二分类 [benign=0, malware=1]

    结构:
      Conv2d(1, 16, 3, padding=1) → BN → ReLU → MaxPool(2)   →  16x32x32
      Conv2d(16, 32, 3, padding=1) → BN → ReLU → MaxPool(2)  →  32x16x16
      Conv2d(32, 64, 3, padding=1) → BN → ReLU → MaxPool(2)  →  64x8x8
      Conv2d(64, 128, 3, padding=1) → BN → ReLU → MaxPool(2) → 128x4x4
      Flatten → Linear(128*4*4, 256) → ReLU → Dropout(dropout)
      Linear(256, 2)
    """

    def __init__(self, num_classes=2, input_size=IMG_SIZE, input_channels=IMG_CHANNELS,
                 dropout=DROPOUT):
        super().__init__()

        self.features = nn.Sequential(
            # Block 1
            nn.Conv2d(input_channels, 16, kernel_size=3, padding=1),
            nn.BatchNorm2d(16),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(2),  # 64→32

            # Block 2
            nn.Conv2d(16, 32, kernel_size=3, padding=1),
            nn.BatchNorm2d(32),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(2),  # 32→16

            # Block 3
            nn.Conv2d(32, 64, kernel_size=3, padding=1),
            nn.BatchNorm2d(64),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(2),  # 16→8

            # Block 4
            nn.Conv2d(64, 128, kernel_size=3, padding=1),
            nn.BatchNorm2d(128),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(2),  # 8→4
        )

        # 计算 flatten 后的尺寸
        feat_size = input_size // 16  # 4 次 MaxPool(2)
        flat_dim = 128 * feat_size * feat_size

        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(flat_dim, 256),
            nn.ReLU(inplace=True),
            nn.Dropout(dropout),
            nn.Linear(256, num_classes),
        )

    def forward(self, x):
        x = self.features(x)
        x = self.classifier(x)
        return x

    def embed(self, x):
        """
        提取倒数第二层(分类头前)的嵌入特征，供 OOD 未知样本检测使用。
        与原 classifier 共享权重：Flatten → Linear(...,256) → ReLU（不含 Dropout，推理时中性）。
        返回: (B, 256)
        """
        f = self.features(x)
        f = self.classifier[0](f)  # Flatten
        f = self.classifier[1](f)  # Linear -> 256
        f = self.classifier[2](f)  # ReLU
        return f


def count_parameters(model):
    """统计可训练参数数量"""
    return sum(p.numel() for p in model.parameters() if p.requires_grad)


if __name__ == "__main__":
    # 测试模型
    model = GuardianCNN()
    print(f"模型参数量: {count_parameters(model):,}")

    # 模拟输入
    dummy = torch.randn(4, 1, IMG_SIZE, IMG_SIZE)
    out = model(dummy)
    print(f"输入: {dummy.shape}  →  输出: {out.shape}")
    print(f"输出值: {out.softmax(dim=1)}")
