# 御天防护型 AI (Guardian AI)

基于「二进制 → 灰度图 + 轻量 CNN」的恶意程序检测引擎，并融合系统监控层，输出**四态融合判定**。适用于本地离线部署，附公共 REST API 供其他程序/设备接入。

## 特性

- **Malware-to-Image 方法**：把 PE（.exe/.dll/.sys/.scr/.com）二进制按字节映射为 64×64 灰度图，交给轻量 CNN 分类。
- **四态融合判定**：综合静态模型与系统监控结果，输出 `良性 / 可疑待审 / 恶意 / 未知` 四种状态。
- **OOD 未知检测**：识别训练分布之外的陌生样本（未见过的恶意程序变种），避免硬分类误判。
- **敏感区域监控**：注册表自启动、启动文件夹、计划任务、载荷高发目录、进程/内存采样等规则联动。
- **公共 API**：`/health`、`/monitor`、`/predict`，Bearer token 鉴权，局域网可用。

## 目录结构

```
御天防护型AI/
├── api_server.py           # 公用 REST API 端口
├── config.py               # 全局配置（路径/超参/OOD 阈值/API 端口/监控规则）
├── guardian.py             # 四态融合判定
├── infer.py                # 推理与批量扫描
├── seal_samples.py         # 样本 AES-256 加密封存脚本
├── train.py                # 训练脚本（类别加权的 CrossEntropy + LR 调度）
├── data/                   # 二进制→灰度图、数据集加载
├── models/                 # cnn.py（模型）、ood.py（未知样本机制）
├── monitor/                # baseline / events / processmem / scanner 监控模块
├── checkpoints/            # 训练产物：guardian_cnn_v1.pth、ood_stats.npz
├── samples/                # 明文样本目录（训练后建议封存清空）
├── training_samples/       # 原始下载的带日志 zip 样本包
└── monitor_data/           # 本地敏感数据（token、封存密码、基线），勿提交到仓库
```

## 四态融合判定

监控层给出风险分与初步判定，静态模型给出分类与置信度，二者融合：

| 融合状态 | 说明 |
|---------|------|
| `benign`（良性） | 静态置信度高且无显著风险信号 |
| `suspicious`（可疑待审） | 命中监控规则存在风险信号，需人工复核 |
| `malicious`（恶意） | 静态分类为恶意或风险信号强 |
| `unknown`（未知） | OOD 判定为训练分布之外，模型不确定 |

## OOD 未知样本机制

在 CNN 倒数第二层（256 维嵌入特征）上，对已知类拟合高斯统计，采用**双阈值**判定未知：

- **Mahalanobis 距离**：样本嵌入到已知类簇的距离超过 `OOD_MAHAL_THRESHOLD`（默认 40.0，按真实训练集 P99≈31 标定）即判未知。
- **Softmax 置信度**：最高类别置信度低于 `OOD_CONF_THRESHOLD`（默认 0.60）也判未知。

> 训练结束后会落盘 `checkpoints/ood_stats.npz`，供推理/API 复用同一套 OOD 拟合。

## 训练 / 重训

依赖（安装到 F 盘）：

```
F:\Python314\python.exe -m pip install -r requirements.txt pyzipper
```

准备样本：把恶意样本放入 `samples/malware/`、良性样本放入 `samples/benign/`（仅 PE 类型，单文件 1KB~10MB），然后训练：

```
F:\Python314\python.exe train.py --epochs 20
```

要点：

- 类别加权 `CrossEntropyLoss` 缓解恶意/良性样本不平衡。
- `ReduceLROnPlateau` 学习率衰减 + 早停；最优模型按恶意类 F1 选择。
- 独立测试集（默认 15%）在训练后单独评估。
- 随机种子固定（`SEED=42`），结果可复现。

## 样本封存（安全）

训练数据涉及恶意样本，敏感。`seal_samples.py` 会把 `samples/malware` 与 `samples/benign` 打包为 AES-256 加密 zip 并删除本地明文：

```
F:\Python314\python.exe seal_samples.py --target G:/御天防护型AI/样本封存
```

- 密码自动生成并保存在本地 `monitor_data/seal_passphrase.txt`，**请务必另行保管**，丢失则样本无法解锁。
- 封存清单见 `monitor_data/seal_manifest.json`。
- 需要重训时再解封明文；`image_cache` 可复用但**不含标签**，重训必须以解封后的 samples 为准。

## 公共 API

启动：

```
F:\Python314\python.exe api_server.py            # 默认 0.0.0.0:8567
F:\Python314\python.exe api_server.py --port 9000
```

### 鉴权 token

- token 存于 `monitor_data/api_token.txt`，可通过环境变量 `GUARDIAN_API_TOKEN` 覆盖。
- 除 `/health` 外，一律要求请求头 `Authorization: Bearer <token>`。

### GET /health —— 健康检查（无鉴权）

```bash
curl http://127.0.0.1:8567/health
```

### GET /monitor —— 拉取敏感区域监控结果

```bash
curl http://127.0.0.1:8567/monitor -H "Authorization: Bearer <token>"
```

### POST /predict —— 上传文件做融合判定

```bash
curl http://127.0.0.1:8567/predict \
     -H "Authorization: Bearer <token>" \
     -F "file=@C:/path/to/your_file.exe"
```

返回 `label / confidence / probabilities / fused_state / monitor`，其中 `fused_state` 即四态判定结果。

## 说明

- 本项目为离线/局域网自用安全工具，请仅在合法授权范围内使用样本。
- 封存密码、API token、真实样本等敏感数据**一律不进入版本库**（见 `.gitignore`）。