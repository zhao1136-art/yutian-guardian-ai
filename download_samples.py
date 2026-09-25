"""
恶意样本批量下载脚本 — MalwareBazaar (abuse.ch)
通过社区 API v1 拉取最近出现的 PE 恶意样本，解压后按 sha256 命名存入 samples\\malware。

用法:
  set MALWAREBAZAAR_AUTH_KEY=<你的 Auth-Key>   (或 --auth-key)
  python download_samples.py --count 1600

安全: 只接受合法授权研究用途；下载的样本属训练数据，训练后须走 seal_samples.py 加密封存。
"""
import io  # noqa
import os
import sys
import glob
import json
import time
import zipfile
import hashlib
import argparse
import concurrent.futures

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import MALWARE_DIR, VALID_EXTENSIONS, MAX_FILE_SIZE, MIN_FILE_SIZE

API = "https://mb-api.abuse.ch/api/v1/"
HEAD = {}
UA = {"User-Agent": "GuardianAI-research/1.0"}


def api_post(data):
    """POST 到 MalwareBazaar API；返回 (ok, payload)。"""
    try:
        r = requests.post(API, data=data, headers={**HEAD, **UA},
                          timeout=60)
    except requests.RequestException as e:
        return False, {"error": str(e)}
    if r.status_code != 200:
        return False, {"error": f"HTTP {r.status_code}"}
    try:
        return True, r.json()
    except Exception:
        # get_file 成功时返回的是 zip 而非 JSON
        return False, {"error": "非 JSON 响应", "raw": r.content}


def collect_candidates(need):
    """拉取最近出现且符合扩展名/大小限制的样本元数据，返回 sha256 列表。"""
    cands = {}
    windows = [("96h", 96), ("24h", 24), ("12h", 12), ("1h", 1)]
    for _tag, hours in windows:
        if len(cands) >= need * 2:
            break
        ok, pl = api_post({"query": "get_recent", "selector": "time",
                           "time": hours})
        if not ok or pl.get("query_status") != "ok":
            continue
        for row in pl.get("data", []):
            h = row.get("sha256_hash")
            if not h or h in cands:
                continue
            ftype = (row.get("file_type") or "").lower()
            size = row.get("file_size") or 0
            if ftype not in ("exe", "dll") or size > MAX_FILE_SIZE:
                continue
            cands[h] = size
        time.sleep(1.0)  # fair use：get_recent 每 5 分钟一次，宽松点
    return list(cands.keys())


def fetch_one(hash_):
    """下载单个样本；成功返回 zip 内容，失败返回 None。"""
    ok, pl = api_post({"query": "get_file", "hash": hash_})
    if ok and pl.get("query_status") == "ok":
        return pl.get("raw")
    if isinstance(pl, dict) and pl.get("error"):
        return None
    return None


def extract_and_save(zip_bytes, out_dir):
    """解压 zip，取第一个 PE 文件，按 sha256 命名保存。成功返回文件名。"""
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            names = [n for n in zf.namelist()
                     if os.path.splitext(n)[1].lower() in VALID_EXTENSIONS]
            if not names:
                return None
            data = zf.read(names[0])
    except Exception:
        return None
    if not (MIN_FILE_SIZE <= len(data) <= MAX_FILE_SIZE):
        return None
    sha = hashlib.sha256(data).hexdigest()
    ext = os.path.splitext(names[0])[1].lower()
    dest = os.path.join(out_dir, sha + ext)
    if os.path.isfile(dest):  # 去重
        return os.path.basename(dest)
    with open(dest, "wb") as f:
        f.write(data)
    return os.path.basename(dest)


def main():
    ap = argparse.ArgumentParser(description="MalwareBazaar 恶意样本批量下载")
    ap.add_argument("--auth-key", default=os.environ.get("MALWAREBAZAAR_AUTH_KEY", ""))
    ap.add_argument("--count", type=int, default=800)
    ap.add_argument("--out", default=MALWARE_DIR)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--sleep", type=float, default=0.3, help="get_file 请求间隔秒")
    args = ap.parse_args()

    key = args.auth_key.strip()
    if not key:
        sys.exit("缺少 Auth-Key：请到 https://auth.abuse.ch/ 免费注册，"
                 "再通过环境变量 MALWAREBAZAAR_AUTH_KEY 或 --auth-key 传入")
    HEAD["Auth-Key"] = key

    os.makedirs(args.out, exist_ok=True)
    existing = {os.path.splitext(os.path.basename(p))[0]
                for p in glob.glob(os.path.join(args.out, "*"))}
    print(f"已有样本 {len(existing)} 个，目标新增 {args.count} 个")

    # 1) 收集候选 hash
    print("正在收集候选 hash ...")
    cands = [h for h in collect_candidates(args.count) if h not in existing]
    print(f"候选 {len(cands)} 个 (去重后)")

    # 2) 并发下载
    ok_n, fail_n, empty = 0, 0, []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(fetch_one, h): h for h in cands}
        for fut in concurrent.futures.as_completed(futs):
            h = futs[fut]
            try:
                blob = fut.result()
            except Exception:
                blob = None
            if not blob:
                empty.append(h)
                fail_n += 1
                continue
            saved = extract_and_save(blob, args.out)
            if saved:
                ok_n += 1
                print(f"[{ok_n}/{args.count}] {saved[:16]}... <- {h[:16]}")
            else:
                fail_n += 1
            if ok_n >= args.count:
                break
            time.sleep(args.sleep)

    total = len({os.path.splitext(os.path.basename(p))[0]
                 for p in glob.glob(os.path.join(args.out, "*"))})
    print(f"\n完成：新增 {ok_n}，失败 {fail_n}，目录现存 {total}")
    if ok_n < args.count:
        print(f"未达目标，还差 {args.count - ok_n} 个（候选耗尽或下载受限）")


if __name__ == "__main__":
    main()
