"""
良性样本采集脚本 — 从 C:\\Windows\\System32 收集合法系统 PE 文件，
按 sha256 命名存入 samples\\benign（扩展名/大小过滤 + 去重）。

用法:
  python collect_benign.py --count 1600

安全: 仅拷贝系统自带文件，不改动源文件。
"""
import os
import sys
import glob
import hashlib
import argparse
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import BENIGN_DIR, VALID_EXTENSIONS, MAX_FILE_SIZE, MIN_FILE_SIZE

SRC = r"C:\Windows\System32"


def main():
    ap = argparse.ArgumentParser(description="System32 良性样本采集")
    ap.add_argument("--count", type=int, default=1600)
    ap.add_argument("--out", default=BENIGN_DIR)
    ap.add_argument("--src", default=SRC)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    existing = {os.path.splitext(os.path.basename(p))[0]
                for p in glob.glob(os.path.join(args.out, "*"))}

    seen = set(existing)
    ok_n, skip_n = 0, 0
    for fp in glob.glob(os.path.join(args.src, "*")):
        if ok_n >= args.count:
            break
        if not os.path.isfile(fp):
            continue
        ext = os.path.splitext(fp)[1].lower()
        if ext not in VALID_EXTENSIONS:
            continue
        size = os.path.getsize(fp)
        if not (MIN_FILE_SIZE <= size <= MAX_FILE_SIZE):
            continue
        sha = hashlib.sha256(open(fp, "rb").read()).hexdigest()
        if sha in seen:
            skip_n += 1
            continue
        seen.add(sha)
        shutil.copyfile(fp, os.path.join(args.out, sha + ext))
        ok_n += 1

    total = len({os.path.splitext(os.path.basename(p))[0]
                 for p in glob.glob(os.path.join(args.out, "*"))})
    print(f"完成：新增 {ok_n}，跳过重复 {skip_n}，目录现存 {total}")
    if ok_n < args.count:
        print(f"未达目标，还差 {args.count - ok_n} 个（源文件不够）")


if __name__ == "__main__":
    main()
