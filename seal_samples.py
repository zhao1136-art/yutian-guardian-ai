"""
样本封存脚本 — 把 samples\\malware 与 samples\\benign 里的明文 PE
打包成 AES-256 加密 zip 放到 G 盘，成功后删除本地明文。

用法: python seal_samples.py [--target G:/御天防护型AI/样本封存]
安全: 密码由脚本自动生成并存本地(monitor_data/seal_passphrase.txt)；删除明文前会校验 zip 内完整。
"""
import os
import sys
import io  # noqa
import glob
import json
import secrets
import hashlib
import datetime
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import MALWARE_DIR, BENIGN_DIR, MONITOR_DIR

try:
    import pyzipper
except ImportError:
    sys.exit("需要 pyzipper，请先: F:\\Python314\\python.exe -m pip install pyzipper")

DEFAULT_TARGET = r"G:\御天防护型AI\样本封存"
PASSFILE = os.path.join(MONITOR_DIR, "seal_passphrase.txt")
MANIFEST = os.path.join(MONITOR_DIR, "seal_manifest.json")


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def collect(src):
    return sorted(glob.glob(os.path.join(src, "*")))


def write_encrypted_zip(out_path, password, files, label):
    """AES-256 加密写入；返回 {zip内文件名: sha256}"""
    record = {}
    with pyzipper.AESZipFile(out_path, "w", compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode())
        for fp in files:
            arc = f"{label}/{os.path.basename(fp)}"
            zf.write(fp, arc)
            record[arc] = _sha256(fp)
    return record


def verify_zip(zip_path, password, record):
    """重开加密包核对每个条目 hash，全部匹配才返回 True"""
    with pyzipper.AESZipFile(zip_path, "r") as zf:
        zf.setpassword(password.encode())
        names = set(zf.namelist())
        if names != set(record):
            return False, f"条目不一致: {names ^ set(record)}"
        for arc, want in record.items():
            data = zf.read(arc)
            if hashlib.sha256(data).hexdigest() != want:
                return False, f"{arc} 校验失败"
    return True, "ok"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=DEFAULT_TARGET)
    ap.add_argument("--keep", action="store_true", help="打包后不删明文(默认会删)")
    args = ap.parse_args()

    os.makedirs(args.target, exist_ok=True)
    os.makedirs(MONITOR_DIR, exist_ok=True)

    mw = collect(MALWARE_DIR)
    bg = collect(BENIGN_DIR)
    print(f"恶意样本: {len(mw)} 个，良性样本: {len(bg)} 个")
    if not mw and not bg:
        sys.exit("两个目录都空，无需封存。")

    # 生成/复用密码
    if os.path.isfile(PASSFILE):
        password = open(PASSFILE, encoding="utf-8").read().strip()
        print("复用已有密码。")
    else:
        password = secrets.token_urlsafe(24)
        with open(PASSFILE, "w", encoding="utf-8") as f:
            f.write(password)
        print(f"已生成新密码，存至: {PASSFILE}")

    stamp = datetime.datetime.now().strftime("%Y%m%d")
    manifest = {"saved_at": datetime.datetime.now().isoformat(),
                "target": args.target, "password_file": PASSFILE, "packages": {}}

    ok = True
    for label, files, zipname in (("malware", mw, f"malware_{stamp}.zip"),
                                  ("benign", bg, f"benign_{stamp}.zip")):
        if not files:
            continue
        zpath = os.path.join(args.target, zipname)
        if os.path.isfile(zpath):
            os.remove(zpath)
        record = write_encrypted_zip(zpath, password, files, label)
        good, msg = verify_zip(zpath, password, record)
        if not good:
            print(f"[FAIL] {label}: 校验未通过 - {msg}")
            ok = False
            continue
        manifest["packages"][label] = {"zip": zpath, "count": len(files),
                                       "sha256": _sha256(zpath)}
        print(f"[OK] {label}: {len(files)} 个已加密打包并校验通过 -> {zpath}")

    if not ok:
        sys.exit("存在校验失败，未删除任何明文。")

    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    if not args.keep:
        for src in (MALWARE_DIR, BENIGN_DIR):
            n = 0
            for fp in collect(src):
                os.remove(fp)
                n += 1
            print(f"已删除明文目录 {src} 下 {n} 个文件")
    print("封存完成。清单:", MANIFEST)
    print("密码文件:", PASSFILE, "(务必妥善保管，丢失则样本无法解锁)")


if __name__ == "__main__":
    main()