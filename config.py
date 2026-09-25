"""
御天防护型 AI — 全局配置
二进制→灰度图 + 轻量 CNN（Malware-to-Image 方法）
"""
import os

# ============ 路径 ============
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
MALWARE_DIR = os.path.join(SAMPLES_DIR, "malware")
BENIGN_DIR = os.path.join(SAMPLES_DIR, "benign")
IMAGE_CACHE_DIR = os.path.join(BASE_DIR, "image_cache")
CHECKPOINT_DIR = os.path.join(BASE_DIR, "checkpoints")

# ============ 图像参数 ============
# 64x64 适合 CPU 训练；若服务器内存充足可改 128x128
IMG_SIZE = 64
# 灰度图通道数
IMG_CHANNELS = 1

# ============ 随机种子（可复现性） ============
SEED = 42
# CPU 推理线程数（0 = 由 PyTorch 自动决定）; 用于推理侧热加载
TORCH_THREADS = 0

# ============ 训练超参数 ============
BATCH_SIZE = 32
LEARNING_RATE = 1e-3
EPOCHS = 20
# 独立测试集比例（从样本中额外留出，训练/验证不使用；0 = 不划分）
TEST_RATIO = 0.15
# 训练集 / 验证集划分比例（针对剔除测试集后的其余样本）
VAL_RATIO = 0.2
# 最优模型保存依据: "f1"（恶意类F1，更适合恶意检测）或 "acc"
BEST_METRIC = "f1"
# 学习率调度器（ReduceLROnPlateau）与早停参数
LR_PATIENCE = 3       # 验证指标不再下降多少 epoch 后降低学习率
LR_FACTOR = 0.5        # 学习率衰减系数
EARLY_STOP_PATIENCE = 8  # 验证指标连续不提升多少 epoch 后提前停止（0 = 关闭）
# 每类最大样本数（防止服务器磁盘爆满，0=不限制）
MAX_SAMPLES_PER_CLASS = 1600

# ============ 样本过滤 ============
# 只处理这些扩展名
VALID_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".com"}
# 单个样本最大字节数（10MB，过大跳过）
MAX_FILE_SIZE = 10 * 1024 * 1024
# 单个样本最小字节数（1KB，太小无意义）
MIN_FILE_SIZE = 1024

# ============ 下载参数 ============
# bazaar.abuse.ch 每次拉取数量（最大 1000）
BAZAAR_BATCH_SIZE = 100
# 下载总量上限
BAZAAR_MAX_DOWNLOAD = 800
# 下载超时秒数
DOWNLOAD_TIMEOUT = 60

# ============ 模型保存 ============
MODEL_NAME = "guardian_cnn_v1.pth"
MODEL_PATH = os.path.join(CHECKPOINT_DIR, MODEL_NAME)

# ============ 模型结构 ============
DROPOUT = 0.5  # 分类头 dropout 概率

# ============ OOD 未知样本机制 ============
# 在 CNN 倒数第二层(嵌入特征 256 维)上拟合已知类高斯统计，用于识别陌生样本
OOD_STATS_FILE = os.path.join(CHECKPOINT_DIR, "ood_stats.npz")
# 嵌入特征维度（与分类头 Linear(256, 2) 的输入一致）
OOD_EMBED_DIM = 256
# Mahalanobis 距离超过该值判定为"未知"(距离已知类簇太远)
# 标定依据：训练集已知样本距离 P99≈31，取 40 留 ~1.3x 余量
OOD_MAHAL_THRESHOLD = 40.0
# 最高类别 softmax 置信度低于该值也判定为"未知"(模型不确定)
OOD_CONF_THRESHOLD = 0.60
# 拟合协方差时的正则(对角抖动)，保证可逆且抑制过拟合
OOD_COV_REG = 1e-3

# ============ 公用 API 端口 ============
API_HOST = "0.0.0.0"
API_PORT = 8567
# API 鉴权 token：为空则自动生成并存 monitor_data/api_token.txt；可被环境变量 GUARDIAN_API_TOKEN 覆盖
# 公用 API 上传上限：真实恶意样本（加壳/打包）常超过 10MB，放宽到 200MB
API_MAX_UPLOAD = 200 * 1024 * 1024
# 前端控制台静态产物目录（React 构建输出，由本服务同端口托管）
STATIC_WEB = os.path.join(BASE_DIR, "static_web")

# ============ 敏感区域监控模块 ============
MONITOR_DIR = os.path.join(BASE_DIR, "monitor_data")
BASELINE_FILE = os.path.join(MONITOR_DIR, "baseline.json")
# 判定为“可疑待审”的规则风险分阈值（0-100）
SUSPICIOUS_SCORE = 40
# 事件日志：只读取最近多少分钟的事件做检查
EVENT_LOOKBACK_MINUTES = 60
# 载荷高发区（出现陌生 PE/脚本即扣风险分）
PAYLOAD_DIRS = ["%TEMP%", "%APPDATA%\\Roaming", "%PROGRAMDATA%", "%APPDATA%\\Local\\Temp"]
# 进程/内存监控（接入精简后的 memtool 纯 CLI 采样器）
MEMTOOL_PATH = os.path.join(BASE_DIR, "内存分析", "ncyh", "bin", "memtool.exe")
# 单进程工作集高于此值(MB)且非白名单，标记为“内存异常”并赋予风险分
HIGH_WS_MB = 800
# 疑似伪装/变体进程名（大小写不敏感，含尾部空格变体）
SUSP_PROC_NAMES = {
    "scvhost.exe", "svch0st.exe", "svchost .exe", "winl0gon.exe",
    "lsas.exe", "expl0rer.exe", "csrss .exe", "svchos.exe",
}
# 规则全名 → 风险分
RULE_WEIGHTS = {
    "registry_autostart_run": 25,
    "registry_autostart_winlogon": 30,
    "registry_appinit": 35,
    "registry_services_autostart": 28,
    "startup_folder_new": 25,
    "scheduled_task_susp": 30,
    "service_imagepath_susp": 35,
    "payload_dir_new_pe": 20,
    "event_process_susp": 18,
    "proc_susp_name": 35,
    "proc_high_ws": 15,
}

# ============ 特征签名库（本地检测用） ============
SIG_DIR = os.path.join(BASE_DIR, ".trae")
# 恶意文件 MD5 特征库（每行一个 32 位十六进制）
SIG_MD5_FILE = os.path.join(SIG_DIR, "扫描-病毒特征库20260419.txt")
# 字节签名库（offset,hexbytes,label）
SIG_VIRUS_DAT = os.path.join(SIG_DIR, "virus.dat")

# ============ 自动建目录 ============
for _d in [SAMPLES_DIR, MALWARE_DIR, BENIGN_DIR, IMAGE_CACHE_DIR,
           CHECKPOINT_DIR, MONITOR_DIR]:
    os.makedirs(_d, exist_ok=True)
