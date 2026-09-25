# 御天防护型 AI (Guardian AI)

基于「二进制 → 灰度图 + 轻量 CNN」的恶意程序检测引擎，并融合系统监控层，输出**四态融合判定**。适用于本地离线部署，附公共 REST API 供其他程序/设备接入。

## 特性

- **Malware-to-Image 方法**：把 PE（.exe/.dll/.sys/.scr/.com）二进制按字节映射为 64×64 灰度图，交给轻量 CNN 分类。
- **四态融合判定**：综合静态模型与系统监控结果，输出 `良性 / 可疑待审 / 恶意 / 未知` 四种状态。
- **OOD 未知检测**：识别训练分布之外的陌生样本（未见过的恶意程序变种），避免硬分类误判。
- **特征签名库**：MD5 哈希特征库 + 字节签名库（银狐家族等），`sigscan.py` 命中即恶意。
- **敏感区域监控**：注册表自启动、启动文件夹、计划任务、载荷高发目录、进程/内存采样等规则联动。
- **公共 API**：`/health`、`/monitor`、`/predict`、`/explain`，Bearer token 鉴权，局域网可用。
- **前端可视化控制台**：纯 SVG 自绘（无第三方图表库）——风险仪表盘、嵌入空间散点图（PCA 2D）、信号强度面板、监控风险分布图，让检测情况"直观可见"。
- **AI 对话（四按钮）**：自研本地解释引擎（无外部大模型、纯离线），点击「结论摘要 / 判定依据 / 处置建议 / 风险程度」直接展示对应结论与答案，并附**相似样本依据**（知识库最近邻）。
- **自动鉴权**：前端打开控制台自动注入 token，无需手动输入；外部 API 调用仍须 `Bearer` 头。

## 目录结构

```
御天防护型AI/
├── api_server.py           # 公用 REST API 端口
├── config.py               # 全局配置（路径/超参/OOD 阈值/API 端口/监控规则）
├── guardian.py             # 四态融合判定
├── infer.py                # 推理与批量扫描
├── sigscan.py              # 特征签名检测（MD5 库 + 字节签名库）
├── viz_pca.py              # 256 维嵌入 → PCA 2D 投影（前端散点图）
├── seal_samples.py         # 样本 AES-256 加密封存脚本
├── train.py                # 训练脚本（类别加权的 CrossEntropy + LR 调度）
├── extract_training_zip.py # 解压原始样本 zip（加密包）→ 提取 PE
├── collect_benign.py       # 从 System32 收集良性样本
├── data/                   # 二进制→灰度图、数据集加载
├── models/                 # cnn.py（模型）、ood.py（未知样本机制）、knowledge.py（特征知识库）
├── monitor/                # baseline / events / processmem / scanner 监控模块
├── web_console/            # 前端控制台（React/Vite，src/components 含 Viz.jsx 可视化组件）
├── checkpoints/            # 训练产物：guardian_cnn_v1.pth、ood_stats.npz、knowledge.*
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

启动（同端口托管前端控制台）：

```
F:\Python314\python.exe api_server.py            # 默认 0.0.0.0:8567
F:\Python314\python.exe api_server.py --port 9000
```

浏览器打开 `http://127.0.0.1:8567/` 即进入**前端控制台**（需先构建前端，见下）。

### 鉴权 token

- token 存于 `monitor_data/api_token.txt`，可通过环境变量 `GUARDIAN_API_TOKEN` 覆盖。
- **前端控制台自动鉴权**：`api_server` 托管页面时自动把 token 注入 localStorage，打开即登录，无需手动输入。
- 外部 API 调用一律要求请求头 `Authorization: Bearer <token>`（`/health` 除外）。

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

- 上传上限 **200MB**（真实加壳/打包样本常超 10MB）。
- 返回 `label / confidence / probabilities / fused_state / monitor / viz`：
  - `fused_state` 即四态判定结果；
  - `viz` 为 PCA 2D 投影坐标与良/恶意历史样本簇点，供前端散点图渲染；
  - `embedding`（256 维）供 `/explain` 做知识库最近邻检索。

### POST /explain —— 自研本地解释引擎（AI 对话）

无需大模型、纯离线。前端提供四个固定问题按钮，点击即展示对应答案：**结论摘要 / 判定依据 / 处置建议 / 风险程度**。接口也可直接调用：

```bash
curl http://127.0.0.1:8567/explain \
     -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
     -d '{"message":"为什么这么判定","detection_context":{"fused_state":"恶意","probabilities":{"benign":0.03,"malware":0.97},"monitor":{"risk_score":0,"findings":[]}}}'
```

- `message` 缺省时返回完整结构化分析（`summary / rationale / evidence / advice / severity / score_hint`）。
- `message` 通过关键字意图识别回答常见追问（为什么/依据/怎么办/风险/结论等）。
- 返回附 `top_matches`：检测嵌入在特征知识库中的最近邻历史样本（相似度 + 类标），作为"相似样本依据"。

## 前端控制台（构建）

```powershell
# 已装 Node 到 F:\nodejs\node-v24.21.0-win-x64
$node = "F:\nodejs\node-v24.21.0-win-x64"; $env:PATH = "$node;$env:PATH"
Set-Location F:\御天防护型AI\web_console
npm install
npm run build        # 产物输出到 ../static_web，由 api_server 同端口托管
```

开发模式：`npm run dev`（vite:5173）会把 `/health /predict /monitor /explain` 代理到后端 8567，需先启动 `api_server.py`。

### 控制台可视化（纯 SVG 自绘，无第三方图表库）

- **样本检测页**：风险仪表盘（指针按融合判定定级）、恶意/良性概率对比条、嵌入空间散点图（本样本 × 良/恶意簇）、信号强度面板（CNN / 签名 / 监控三信号）。
- **系统监控页**：风险分仪表盘 + 风险来源按规则分组分布条 + 明细列表。
- **AI 对话页**：四个结论按钮 + 答案卡片 + 相似样本依据标签。

## 说明

- 本项目为离线/局域网自用安全工具，请仅在合法授权范围内使用样本。
- 封存密码、API token、真实样本等敏感数据**一律不进入版本库**（见 `.gitignore`）。