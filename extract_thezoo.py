"""
theZoo 恶意样本提取脚本 — 从 .trae/theZoo-0.60.zip 解出真实 PE 样本。
每个样本目录含加密 zip + .pass（密码）；用密码解压后按内容 sha256 命名
存入 samples\\malware（扩展名/大小过滤 + 去重）。

用法:
  python extract_thezoo.py
"""
import os
import sys
import io
import glob
import zipfile
import hashlib
import argparse
import concurrent.futures

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import MALWARE_DIR, VALID_EXTENSIONS, MAX_FILE_SIZE, MIN_FILE_SIZE

ZIP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        ".trae", "theZoo-0.60.zip")


def collect_jobs(zf):
    """返回 [(内层zip路径, 候选密码列表), ...]"""
    zips = [n for n in zf.namelist()
            if n.lower().endswith(".zip") and "/malwares/" in n]
    jobs = []
    for arc in zips:
        d = os.path.dirname(arc)
        passfile = next((n for n in zf.namelist()
                         if n.startswith(d + "/") and n.endswith(".pass")), None)
        pwds = [b"infected"]
        if passfile:
            raw = zf.read(passfile)
            for v in (raw, raw.strip(), raw.strip() + b" "):
                if v not in pwds:
                    pwds.append(v)
        jobs.append((arc, pwds))
    return jobs


def process_job(zf, arc, pwds):
    """解压内层 zip，返回 [(扩展名, 内容), ...]；失败返回 []。"""
    blob = zf.read(arc)
    for pwd in pwds:
        try:
            inner = zipfile.ZipFile(io.BytesIO(blob))
        except Exception:
            continue
        try:
            inner.setpassword(pwd)
            out = []
            for item in inner.infolist():
                ext = os.path.splitext(item.filename)[1].lower()
                if ext not in VALID_EXTENSIONS:
                    continue
                data = inner.read(item.filename)
                if not (MIN_FILE_SIZE <= len(data) <= MAX_FILE_SIZE):
                    continue
                if data[:2] != b"MZ":
                    continue
                out.append((ext, data))
            if out:
                return out
        except Exception:
            continue
    return []


def main():
    ap = argparse.ArgumentParser(description="theZoo 恶意样本提取")
    ap.add_argument("--out", default=MALWARE_DIR)
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    existing = {os.path.splitext(os.path.basename(p))[0]
                for p in glob.glob(os.path.join(args.out, "*"))}
    print(f"已有样本 {len(existing)} 个")

    with zipfile.ZipFile(ZIP_PATH) as zf:
        jobs = collect_jobs(zf)
        print(f"内层加密 zip 共 {len(jobs)} 个")
        saved = set(existing)
        ok_n, fail_n = 0, 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = [ex.submit(process_job, zf, arc, pwds) for arc, pwds in jobs]
            for fut, (arc, _p) in zip(futs, jobs):
                for ext, data in fut.result():
                    sha = hashlib.sha256(data).hexdigest()
                    if sha in saved:
                        continue
                    with open(os.path.join(args.out, sha + ext), "wb") as f:
                        f.write(data)
                    saved.add(sha)
                    ok_n += 1
                    print(f"[{ok_n}] {sha[:16]}...{ext} <- {arc}")
                fail_n += 1

    total = len({os.path.splitext(os.path.basename(p))[0]
                 for p in glob.glob(os.path.join(args.out, "*"))})
    print(f"\n完成：新增 {ok_n} 个，目录现存 {total}")


if __name__ == "__main__":
    main()
