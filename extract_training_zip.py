"""
原始样本 zip 包提取脚本 — 解压 training_samples\\*.zip 里的 PE 文件，
校验 MZ 头/大小，按内容 sha256 去重命名存入 samples\\malware。

用法:
  python extract_training_zip.py
"""
import os
import sys
import glob
import shutil
import zipfile
import hashlib
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import MALWARE_DIR, VALID_EXTENSIONS, MAX_FILE_SIZE, MIN_FILE_SIZE

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "training_samples")
PASSWORD = b"infected"  # 样本包统一密码（与 theZoo 同款）
MOVETO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "training_samples")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=SRC, help="扫描 zip 的目录")
    ap.add_argument("--move", default=MOVETO, help="解压后把 zip 移到的目录(留空不移)")
    ap.add_argument("--limit", type=int, default=1600, help="样本总数达到该值即停")
    args = ap.parse_args()
    src = args.src
    os.makedirs(MALWARE_DIR, exist_ok=True)
    existing = {os.path.splitext(os.path.basename(p))[0]
                for p in glob.glob(os.path.join(MALWARE_DIR, "*"))}
    print(f"已有样本 {len(existing)} 个")

    saved = set(existing)
    ok_n, dup_n, bad_n = 0, 0, 0
    for zp in sorted(glob.glob(os.path.join(src, "*.zip"))):
        try:
            z = zipfile.ZipFile(zp)
        except Exception as e:
            print(f"[ERR] {os.path.basename(zp)}: {e}")
            continue
        for arc in z.namelist():
            ext = os.path.splitext(arc)[1].lower()
            if ext not in VALID_EXTENSIONS:
                continue
            try:
                data = z.read(arc, PASSWORD)
            except Exception:
                bad_n += 1
                continue
            if not (MIN_FILE_SIZE <= len(data) <= MAX_FILE_SIZE):
                bad_n += 1
                continue
            if data[:2] != b"MZ":
                bad_n += 1
                continue
            sha = hashlib.sha256(data).hexdigest()
            if sha in saved:
                dup_n += 1
                continue
            with open(os.path.join(MALWARE_DIR, sha + ext), "wb") as f:
                f.write(data)
            saved.add(sha)
            ok_n += 1
            if ok_n % 100 == 0:
                print(f"... 已提取 {ok_n} 个")
            if len(saved) >= args.limit:
                break
        z.close()
        print(f"[OK] {os.path.basename(zp)}")
        if args.move:
            os.makedirs(args.move, exist_ok=True)
            shutil.move(zp, os.path.join(args.move, os.path.basename(zp)))
        if len(saved) >= args.limit:
            print(f"已达上限 {args.limit}，停止处理后续 zip。")
            break

    total = len({os.path.splitext(os.path.basename(p))[0]
                 for p in glob.glob(os.path.join(MALWARE_DIR, "*"))})
    print(f"\n完成：新增 {ok_n}，重复 {dup_n}，无效 {bad_n}，目录现存 {total}")


if __name__ == "__main__":
    main()
