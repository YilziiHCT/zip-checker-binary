#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZIP / FILE Security & Content Analyzer - Advanced
Dibuat oleh: Yilzi Dev
Deskripsi:
  - Scan file tunggal (txt, md, py, js, sh, docx*) atau arsip (.zip, .tar, .tar.gz/.tgz).
  - Lakukan pemeriksaan menyeluruh: metadata, hash, kompresi, deteksi bahasa,
    pencarian pola berbahaya (heuristik), entropi (deteksi obfuscation), dan scoring risiko.
  - Tampilkan progres dengan animasi spinner dan tabel di terminal.
  - Simpan laporan ke `data_file_yilzidev_<timestamp>.txt` dan opsional JSON/CSV.
Catatan:
  - *Untuk membaca .docx, install: pip install python-docx
  - Tidak mengeksekusi file apa pun — hanya membaca dan menganalisis.
"""

from __future__ import annotations
import os
import sys
import io
import re
import json
import csv
import time
import math
import tarfile
import zipfile
import hashlib
import mimetypes
import argparse
import threading
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

try:
    from tabulate import tabulate
except Exception:
    print("Module 'tabulate' belum terpasang. Jalankan: pip install tabulate")
    sys.exit(1)

DOCX_AVAILABLE = False
try:
    from docx import Document 
    DOCX_AVAILABLE = True
except Exception:
    DOCX_AVAILABLE = False


MAX_READ_BYTES = 5 * 1024 * 1024   
BRAND = "Yilzi Dev"
DEFAULT_OUTPUT_PREFIX = "data_file_yilzidev"
SUSPICIOUS_EXT = {".exe", ".dll", ".bat", ".cmd", ".sh", ".js", ".vbs", ".ps1", ".scr"}

def hash_bytes(b: bytes) -> Dict[str, str]:
    return {
        "md5": hashlib.md5(b).hexdigest(),
        "sha1": hashlib.sha1(b).hexdigest(),
        "sha256": hashlib.sha256(b).hexdigest()
    }

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

class Spinner:
    def __init__(self, text="Scanning"):
        self.text = text
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)
    def _spin(self):
        chars = "|/-\\"
        i = 0
        while not self._stop.is_set():
            print(f"\r{self.text}... {chars[i % len(chars)]}", end="", flush=True)
            time.sleep(0.12)
            i += 1
        print("\r" + " " * (len(self.text) + 8) + "\r", end="", flush=True)
    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
    def stop(self):
        self._stop.set()
        self._thread.join(timeout=0.5)


PATTERNS = {
    "base64_like": re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}"),
    "suspicious_commands": re.compile(rb"(curl|wget|Invoke-Expression|iex|powershell|nc\s|netcat|bash -i|/bin/bash)", re.I),
    "eval_exec": re.compile(rb"\b(eval|exec|System\.)\b", re.I),
    "obfuscated_hex": re.compile(rb"(?:\\x[0-9A-Fa-f]{2}){6,}"),
    "ip_addr": re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "url": re.compile(rb"https?://[^\s'\"`<>]{6,}"),
    "suspicious_imports": re.compile(rb"\b(os|subprocess|socket|ctypes|requests)\b", re.I),
}

def analyze_content_bytes(b: bytes) -> Dict[str, Any]:
    b_sample = b[:MAX_READ_BYTES]
    ent = shannon_entropy(b_sample)
    findings = {}
    total_matches = 0
    for name, pat in PATTERNS.items():
        matches = pat.findall(b_sample)
        findings[name] = len(matches)
        total_matches += len(matches)
    long_lines = sum(1 for line in b_sample.splitlines() if len(line) > 400)
    findings["long_lines"] = long_lines
    findings["entropy"] = ent
    findings["suspicious_score_raw"] = total_matches + (1 if ent > 6.5 else 0) + (1 if long_lines>0 else 0)
    return findings

def detect_language_by_name_and_content(name: str, b: bytes) -> str:
    ext = os.path.splitext(name)[1].lower()
    if ext in {".py"}:
        return "Python"
    if ext in {".js", ".mjs"}:
        return "JavaScript"
    if ext in {".sh", ".bash"}:
        return "Shell"
    if ext in {".ps1"}:
        return "PowerShell"
    if ext in {".php"}:
        return "PHP"
    if ext in {".java"}:
        return "Java"
    if ext in {".c", ".h", ".cpp", ".cxx"}:
        return "C/C++"
    if ext in {".html", ".htm"}:
        return "HTML"
    if ext in {".md", ".txt"}:
        return "Text/Markdown"
    if ext in {".docx"}:
        return "DOCX"
    text_head = b[:256].decode(errors="ignore")
    if text_head.startswith("#!"):
        if "python" in text_head:
            return "Python (script)"
        if "bash" in text_head:
            return "Shell (script)"
    if b.find(b"def ")!=-1 or b.find(b"import ")!=-1:
        return "Python-like"
    if b.find(b"function ")!=-1 or b.find(b"console.log")!=-1:
        return "JavaScript-like"
    return "Unknown/Binary"

def score_risk(meta: Dict[str, Any], findings: Dict[str, Any]) -> Tuple[int, str]:
    """
    Hitung skor risiko 0-100 berdasarkan heuristik:
      - ekstensi berbahaya => +30
      - pola mencurigakan (per match) => +10 per match (dilimit)
      - entropi tinggi => +20
      - long lines / obfuscation => +10
      - executable/binary file => +10
    """
    score = 0
    name = meta.get("name","")
    ext = os.path.splitext(name)[1].lower()
    # extension weight
    if ext in SUSPICIOUS_EXT:
        score += 30
    # compressed ratio anomaly
    ratio = meta.get("compress_ratio", 100)
    if ratio < 8 and meta.get("original_size",0) > 1024:  # sangat kecil => mungkin packed
        score += 10
    # findings
    raw = findings.get("suspicious_score_raw", 0)
    score += min(raw * 12, 40)
    # entropy
    if findings.get("entropy",0) > 7.5:
        score += 20
    elif findings.get("entropy",0) > 6.5:
        score += 10
    # long lines
    if findings.get("long_lines",0) > 0:
        score += 8
    # binary heuristics
    if meta.get("is_binary", False):
        score += 8
    # clamp
    score = max(0, min(100, int(score)))
    if score >= 70:
        level = "Tinggi"
    elif score >= 35:
        level = "Sedang"
    else:
        level = "Rendah"
    return score, level


def is_binary_bytes(b: bytes) -> bool:
    sample = b[:1024]
    if b"\x00" in sample:
        return True
    non_print = sum(1 for c in sample if c < 9 or (c>13 and c<32))
    return (non_print / max(1, len(sample))) > 0.30

def analyze_single_file_bytes(name: str, b: bytes, compressed_size: Optional[int]=None) -> Dict[str, Any]:
    meta = {}
    meta["name"] = name
    meta["original_size"] = len(b)
    meta["compressed_size"] = compressed_size if compressed_size is not None else meta["original_size"]
    meta["compress_ratio"] = (meta["compressed_size"]/meta["original_size"]*100) if meta["original_size"]>0 else 0
    meta["hashes"] = hash_bytes(b if len(b) <= MAX_READ_BYTES else b[:MAX_READ_BYTES])
    meta["is_binary"] = is_binary_bytes(b)
    lang = detect_language_by_name_and_content(name, b)
    meta["detected_type"] = lang
    findings = analyze_content_bytes(b)
    score, level = score_risk(meta, findings)
    return {
        "meta": meta,
        "findings": findings,
        "risk_score": score,
        "risk_level": level
    }

def analyze_zip_path(path: str, verbose_progress: bool=True) -> List[Dict[str,Any]]:
    results = []
    with zipfile.ZipFile(path, "r") as z:
        members = z.infolist()
        N = len(members)
        for idx, info in enumerate(members, start=1):
            if info.is_dir():
                continue
            name = info.filename
            try:
                data = z.read(info.filename)
            except Exception as e:
                data = b""
            res = analyze_single_file_bytes(name, data, compressed_size=info.compress_size)
            res["meta"]["zip_info"] = {
                "zip_name": os.path.basename(path),
                "zip_index": idx,
                "zip_total": N,
                "modified": datetime(*info.date_time).isoformat()
            }
            results.append(res)
            if verbose_progress:
                print_progress(idx, N, prefix="Memeriksa arsip")
    return results

def analyze_tar_path(path: str, verbose_progress: bool=True) -> List[Dict[str,Any]]:
    results = []
    with tarfile.open(path, "r:*") as t:
        members = [m for m in t.getmembers() if m.isreg()]
        N = len(members)
        for idx, m in enumerate(members, start=1):
            name = m.name
            f = t.extractfile(m)
            data = f.read() if f else b""
            res = analyze_single_file_bytes(name, data, compressed_size=m.size)
            res["meta"]["tar_info"] = {
                "tar_name": os.path.basename(path),
                "tar_index": idx,
                "tar_total": N,
                "modified": datetime.fromtimestamp(m.mtime).isoformat()
            }
            results.append(res)
            if verbose_progress:
                print_progress(idx, N, prefix="Memeriksa arsip tar")
    return results

def analyze_plain_file_path(path: str, verbose_progress: bool=True) -> List[Dict[str,Any]]:
    results = []
    name = os.path.basename(path)
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_READ_BYTES+1)
    except Exception as e:
        data = b""
    if name.lower().endswith(".docx") and DOCX_AVAILABLE:
        try:
            doc = Document(path)
            txt = "\n".join(p.text for p in doc.paragraphs)
            data = txt.encode(errors="ignore")
        except Exception:
            pass
    res = analyze_single_file_bytes(name, data, compressed_size=None)
    results.append(res)
    if verbose_progress:
        print_progress(1, 1, prefix="Memeriksa file tunggal")
    return results


def print_progress(i: int, total: int, prefix="Proses"):
    pct = int(i/total*100) if total>0 else 100
    bar_len = 30
    filled = int(bar_len * i / total) if total>0 else bar_len
    bar = "[" + "#"*filled + "-"*(bar_len-filled) + "]"
    print(f"\r{prefix}: {bar} {i}/{total} ({pct}%)", end="", flush=True)
    if i==total:
        print()

def summary_from_results(results: List[Dict[str,Any]]) -> Dict[str,Any]:
    total = len(results)
    high = sum(1 for r in results if r["risk_level"]=="Tinggi")
    med  = sum(1 for r in results if r["risk_level"]=="Sedang")
    low  = sum(1 for r in results if r["risk_level"]=="Rendah")
    avg_score = sum(r["risk_score"] for r in results)/total if total>0 else 0
    return {
        "total_files": total,
        "high": high, "medium": med, "low": low,
        "avg_score": round(avg_score,2)
    }

def pretty_table_results(results: List[Dict[str,Any]]):
    rows = []
    for r in results:
        m = r["meta"]
        rows.append([
            m.get("name"),
            m.get("detected_type"),
            f"{m.get('original_size',0)} B",
            f"{m.get('compressed_size',0)} B",
            r["risk_score"],
            r["risk_level"]
        ])
    headers = ["Nama File","Tipe","Ukuran","Kompresi","Skor","Risiko"]
    print(tabulate(rows, headers=headers, tablefmt="fancy_grid"))

def save_report_text(results: List[Dict[str,Any]], outpath: str):
    now = datetime.now().isoformat(sep=" ", timespec="seconds")
    with open(outpath, "w", encoding="utf-8") as f:
        f.write("=== ZIP/FILE SECURITY REPORT ===\n")
        f.write(f"Author  : {BRAND}\n")
        f.write(f"Generated: {now}\n\n")
        for r in results:
            m = r["meta"]
            f.write("-"*50 + "\n")
            f.write(f"Nama File : {m.get('name')}\n")
            f.write(f"Tipe      : {m.get('detected_type')}\n")
            f.write(f"Original  : {m.get('original_size')} B\n")
            f.write(f"Compressed: {m.get('compressed_size')} B\n")
            f.write(f"Compress ratio: {m.get('compress_ratio'):.2f}%\n")
            f.write(f"Hashes    : md5={m['hashes']['md5']} sha256={m['hashes']['sha256']}\n")
            f.write(f"Binary?   : {m.get('is_binary')}\n")
            f.write(f"Risk Score: {r['risk_score']} ({r['risk_level']})\n")
            f.write("Findings:\n")
            for k, v in r["findings"].items():
                f.write(f"  - {k}: {v}\n")
            f.write("\n")
        sumry = summary_from_results(results)
        f.write("="*50 + "\n")
        f.write("Ringkasan:\n")
        f.write(f"Total berkas: {sumry['total_files']}\n")
        f.write(f"Risiko Tinggi: {sumry['high']}\n")
        f.write(f"Risiko Sedang: {sumry['medium']}\n")
        f.write(f"Risiko Rendah: {sumry['low']}\n")
        f.write(f"Rata-rata skor: {sumry['avg_score']}\n")
    print(f"[+] Laporan teks disimpan ke: {outpath}")

def save_report_json(results: List[Dict[str,Any]], outpath: str):
    safe = []
    for r in results:
        safe.append({
            "meta": {
                "name": r["meta"].get("name"),
                "detected_type": r["meta"].get("detected_type"),
                "original_size": r["meta"].get("original_size"),
                "compressed_size": r["meta"].get("compressed_size"),
                "compress_ratio": r["meta"].get("compress_ratio"),
                "hashes": r["meta"].get("hashes"),
                "is_binary": r["meta"].get("is_binary"),
            },
            "findings": r["findings"],
            "risk_score": r["risk_score"],
            "risk_level": r["risk_level"]
        })
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump({"generated_by": BRAND, "timestamp": datetime.now().isoformat(), "results": safe}, f, indent=2)
    print(f"[+] Laporan JSON disimpan ke: {outpath}")

def save_report_csv(results: List[Dict[str,Any]], outpath: str):
    with open(outpath, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["name","detected_type","original_size","compressed_size","compress_ratio","md5","sha256","is_binary","risk_score","risk_level"])
        for r in results:
            m = r["meta"]
            w.writerow([m.get("name"), m.get("detected_type"), m.get("original_size"), m.get("compressed_size"),
                        round(m.get("compress_ratio",0),2), m["hashes"]["md5"], m["hashes"]["sha256"], m.get("is_binary"), r["risk_score"], r["risk_level"]])
    print(f"[+] Laporan CSV disimpan ke: {outpath}")


def main():
    parser = argparse.ArgumentParser(prog="zip_checker_advanced.py", description="Scanner file/arsip - Yilzi Dev")
    parser.add_argument("path", nargs="?", help="Path file atau arsip (zip/tar) - jika kosong => interaktif")
    parser.add_argument("-o","--output", help="Nama file output (.txt) (default automatic)", default=None)
    parser.add_argument("--json", help="Simpan juga ke JSON", action="store_true")
    parser.add_argument("--csv",  help="Simpan juga ke CSV", action="store_true")
    parser.add_argument("--no-anim", help="Matikan animasi spinner/progress", action="store_true")
    args = parser.parse_args()

    # interactive jika path kosong
    if not args.path:
        args.path = input("Masukkan path file/arsip: ").strip()
        if not args.path:
            print("Path kosong. Keluar.")
            return

    if not os.path.exists(args.path):
        print(f"[!] File tidak ditemukan: {args.path}")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_base = args.output if args.output else f"{DEFAULT_OUTPUT_PREFIX}_{timestamp}.txt"
    json_out = f"{os.path.splitext(output_base)[0]}.json"
    csv_out  = f"{os.path.splitext(output_base)[0]}.csv"

    spinner = Spinner("Memulai analisis") if not args.no_anim else None
    if spinner:
        spinner.start()

    ext = os.path.splitext(args.path)[1].lower()
    results = []
    try:
        if zipfile.is_zipfile(args.path):
            if spinner:
                spinner.text = "Memindai arsip ZIP"
            results = analyze_zip_path(args.path, verbose_progress=not args.no_anim)
        elif tarfile.is_tarfile(args.path):
            if spinner:
                spinner.text = "Memindai arsip TAR"
            results = analyze_tar_path(args.path, verbose_progress=not args.no_anim)
        elif os.path.isfile(args.path):
            if spinner:
                spinner.text = "Memindai file tunggal"
            results = analyze_plain_file_path(args.path, verbose_progress=not args.no_anim)
        else:
            print("[!] Tipe file tidak dikenali atau bukan regular file.")
    finally:
        if spinner:
            spinner.stop()

    # tampilkan tabel ringkasan di terminal bebas ubah
    print("\n=== Ringkasan Hasil Scan ===")
    pretty_table_results(results)
    sumry = summary_from_results(results)
    print("\nRingkasan singkat:")
    print(f"Total file: {sumry['total_files']}  |  Tinggi: {sumry['high']}  |  Sedang: {sumry['medium']}  |  Rendah: {sumry['low']}  |  Rata-rata skor: {sumry['avg_score']}")

    # simpan laporan ke path
    save_report_text(results, output_base)
    if args.json:
        save_report_json(results, json_out)
    if args.csv:
        save_report_csv(results, csv_out)

    print("\nSelesai. Tetap hati-hati — hasil ini adalah heuristik, bukan verifikasi mutlak.")
    print(f"Author: {BRAND}")

if __name__ == "__main__":
    main()
