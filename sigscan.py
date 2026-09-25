"""
御天防护型 AI — 特征签名检测模块
接入两个本地特征库：
  1) MD5 哈希特征库（扫描-病毒特征库20260419.txt）：文件 MD5 命中即恶意
  2) 字节签名库（virus.dat）：按偏移匹配十六进制字节特征，命中带标签（银狐家族等）

用法: from sigscan import scan, describe
"""
import os
import re
import sys
import hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import SIG_MD5_FILE, SIG_VIRUS_DAT

# 惰性缓存
_md5_db = None
_sigs = None
_MD5_LOADED = False
_SIGS_LOADED = False


def load_md5_db(force=False):
    """加载 MD5 特征库（每行一个 32 位十六进制）为集合。"""
    global _md5_db, _MD5_LOADED
    if _MD5_LOADED and not force:
        return _md5_db
    db = set()
    if SIG_MD5_FILE and os.path.isfile(SIG_MD5_FILE):
        pat = re.compile(r"^[0-9a-fA-F]{32}$")
        with open(SIG_MD5_FILE, encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if pat.match(s):
                    db.add(s.lower())
    _md5_db = db
    _MD5_LOADED = True
    return _md5_db


def load_virus_sigs(force=False):
    """加载字节签名库 virus.dat → [(offset, bytes, label), ...]。
    兼容两种偏移写法：0x 十六进制与十进制。"""
    global _sigs, _SIGS_LOADED
    if _SIGS_LOADED and not force:
        return _sigs
    sigs = []
    if SIG_VIRUS_DAT and os.path.isfile(SIG_VIRUS_DAT):
        with open(SIG_VIRUS_DAT, encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                parts = s.split(",")
                if len(parts) < 3:
                    continue
                try:
                    off = int(parts[0], 0) if parts[0].lower().startswith("0x") \
                        else int(parts[0], 10)
                    blob = bytes.fromhex(parts[1])
                    label = ",".join(parts[2:])
                except ValueError:
                    continue
                if blob:
                    sigs.append((off, blob, label))
    _sigs = sigs
    _SIGS_LOADED = True
    return _sigs


def scan(data):
    """对文件字节做签名检测。
    返回 {md5_hit: bool, sig_hits: [labels], total_hits: int, malicious: bool}
    sig_hits 最多返回 20 条去重标签。"""
    if not data:
        return {"md5_hit": False, "sig_hits": [], "total_hits": 0,
                "malicious": False}
    result = {"md5_hit": False, "sig_hits": [], "total_hits": 0,
              "malicious": False}

    # 1) MD5 命中
    md5_db = load_md5_db()
    if md5_db:
        result["md5_hit"] = hashlib.md5(data).hexdigest() in md5_db

    # 2) 字节签名
    n = len(data)
    labels = []
    for off, blob, label in load_virus_sigs():
        if off + len(blob) <= n and data[off:off + len(blob)] == blob:
            result["total_hits"] += 1
            if label not in labels:
                labels.append(label)
    result["sig_hits"] = labels[:20]

    result["malicious"] = result["md5_hit"] or bool(result["sig_hits"])
    return result


def describe(hit):
    """把 scan() 结果转成可读的命中描述。"""
    if not hit or not hit.get("malicious"):
        return ""
    parts = []
    if hit.get("md5_hit"):
        parts.append("MD5 哈希命中恶意特征库")
    if hit.get("sig_hits"):
        parts.append("字节签名命中: " + "、".join(hit["sig_hits"][:5])
                     + (f" 等共 {hit['total_hits']} 处" if hit["total_hits"] > 5 else ""))
    return "；".join(parts)
