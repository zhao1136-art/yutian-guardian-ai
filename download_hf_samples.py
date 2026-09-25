"""
恶意样本批量下载脚本 — Hugging Face 数据集 unileon-robotics/malware-samples
经 hf-mirror.com 中国镜像下载真实恶意 PE，校验后按内容 sha256 命名存入 samples\\malware。

说明: 数据集目录名为 32 位十六进制(md5)；下载后校验 PE 头(MZ)+大小，
再以内容 sha256 作为文件名与去重键。

用法:
  python download_hf_samples.py --count 1600

安全: 数据集为 CC BY-NC-SA 4.0（非商用，仅限合法授权研究）；下载的样本属
训练数据，训练后须走 seal_samples.py 加密封存。
"""
import os
import sys
import glob
import time
import re
import hashlib
import argparse
import concurrent.futures

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import MALWARE_DIR, VALID_EXTENSIONS, MAX_FILE_SIZE, MIN_FILE_SIZE

MIRROR = "https://hf-mirror.com"
DATASET = "unileon-robotics/malware-samples"
TREE_API = f"{MIRROR}/api/datasets/{DATASET}/tree/main/binaries"
RESOLVE = f"{MIRROR}/datasets/{DATASET}/resolve/main"
PAGE = 1000
UA = {"User-Agent": "GuardianAI-research/1.0"}
ID_RE = re.compile(r"^[0-9a-f]{32}$")  # 数据集目录名 = 32 位 md5


def list_ids(limit):
    """游标分页枚举 binaries/ 下的样本目录，返回 md5 目录名列表。"""
    ids = []
    cursor = ""
    while len(ids) < limit:
        params = {"path": "binaries", "limit": PAGE}
        if cursor:
            params["cursor"] = cursor
        try:
            r = requests.get(TREE_API, params=params, headers=UA, timeout=60)
        except requests.RequestException as e:
            print(f"列表请求失败: {e}")
            break
        if r.status_code != 200:
            print(f"列表 HTTP {r.status_code}")
            break
        data = r.json()
        if not isinstance(data, list):
            print(f"列表响应异常: {data}")
            break
        for ent in data:
            if ent.get("type") == "directory":
                name = os.path.basename(ent.get("path", "").rstrip("/"))
                if ID_RE.match(name):
                    ids.append(name)
        nxt = r.links.get("next", {}).get("url", "")
        cursor = ""
        m = re.search(r"[?&]cursor=([^&]+)", nxt)
        if m:
            cursor = m.group(1)
        print(f"已枚举 {len(ids)} 个样本目录...")
        if not cursor:
            break
        time.sleep(0.3)
    return ids


def fetch_one(did):
    """下载单个样本；成功返回 (扩展名, 内容sha256, 内容)，失败返回 None。"""
    # 该数据集内文件绝大多数为 .exe，优先尝试以减少 404 探测
    for ext in (".exe", ".dll", ".sys", ".scr", ".com"):
        url = f"{RESOLVE}/binaries/{did}/{did}{ext}"
        try:
            r = requests.get(url, headers=UA, timeout=60)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        blob = r.content
        if not (MIN_FILE_SIZE <= len(blob) <= MAX_FILE_SIZE):
            continue
        if blob[:2] != b"MZ":  # PE 头校验，排除错误页
            continue
        return (ext, hashlib.sha256(blob).hexdigest(), blob)
    return None


def main():
    ap = argparse.ArgumentParser(description="HF 数据集恶意样本批量下载")
    ap.add_argument("--count", type=int, default=1600)
    ap.add_argument("--out", default=MALWARE_DIR)
    ap.add_argument("--workers", type=int, default=5)
    ap.add_argument("--sleep", type=float, default=0.4, help="请求间隔秒")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    existing = {os.path.splitext(os.path.basename(p))[0]
                for p in glob.glob(os.path.join(args.out, "*"))}
    print(f"已有样本 {len(existing)} 个，目标新增 {args.count} 个")

    # 1) 枚举候选 md5 目录
    print("正在枚举数据集中的样本目录 ...")
    cands = list_ids(args.count * 2)
    print(f"候选 {len(cands)} 个")

    # 2) 并发下载 + 按内容 sha256 去重
    ok_n, fail_n, dup_n = 0, 0, 0
    saved = set(existing)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(fetch_one, d): d for d in cands}
        for fut in concurrent.futures.as_completed(futs):
            try:
                got = fut.result()
            except Exception:
                got = None
            if not got:
                fail_n += 1
                continue
            ext, sha, blob = got
            if sha in saved:
                dup_n += 1
                continue
            with open(os.path.join(args.out, sha + ext), "wb") as f:
                f.write(blob)
            saved.add(sha)
            ok_n += 1
            print(f"[{ok_n}/{args.count}] {sha[:16]}...{ext}")
            if ok_n >= args.count:
                break
            time.sleep(args.sleep)

    total = len({os.path.splitext(os.path.basename(p))[0]
                 for p in glob.glob(os.path.join(args.out, "*"))})
    print(f"\n完成：新增 {ok_n}，重复 {dup_n}，失败 {fail_n}，目录现存 {total}")
    if ok_n < args.count:
        print(f"未达目标，还差 {args.count - ok_n} 个（候选耗尽或下载受限）")


if __name__ == "__main__":
    main()
