#!/usr/bin/env python3
"""
testssl-swarm.py – Bulk Parallel SSL/TLS Protocol Scanner – Powered by testssl.sh

This script is a Python wrapper around the excellent open-source tool "testssl.sh"
(https://testssl.sh/) by Dirk Wetter and contributors.

Features:
    • Mass scans a list of hosts/IPs for supported SSL/TLS protocol versions
    • Runs testssl.sh in parallel for speed (ThreadPoolExecutor)
    • Displays a live progress bar with the currently processed target
    • Outputs results for SSLv2, SSLv3, TLS1.0, TLS1.1, TLS1.2, TLS1.3
    • Marks "Fail" if any weak protocol (SSLv2, SSLv3, TLS1.0, TLS1.1) is offered
    • Saves all results to a CSV file; optionally dumps raw testssl.sh output

Usage:
    python testssl-swarm.py \
        -i hosts.txt \
        -o results.csv \
        --testssl /path/to/testssl.sh \
        -w 24 \
        --timeout 600 \
        --raw-dump-dir ./raw_logs

Requirements:
    • Python 3
    • tqdm (pip install tqdm)
    • testssl.sh available locally and executable

Credit:
    This script relies entirely on the capabilities of testssl.sh and simply automates
    and parallelizes its execution over many targets.
"""

import argparse, subprocess, os, re, csv, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm  # pip install tqdm

ALL_COLS  = ["SSLv2", "SSLv3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"]
WEAK_COLS = ["SSLv2", "SSLv3", "TLS1.0", "TLS1.1"]

ANSI_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
CTRL_RE = re.compile(r'[\x00-\x09\x0b-\x1a\x1c-\x1f]')

def clean_text(s: str) -> str:
    s = s.replace('\r', '\n')
    s = ANSI_RE.sub('', s)
    s = CTRL_RE.sub('', s)
    s = re.sub(r'\n{2,}', '\n', s)
    return s

PROTO_LABEL_RE = re.compile(
    r'^\s*(SSLv2|SSLv3|TLS\s*1(?:\.[0-3])?|TLSv?1(?:\.[0-3])?)\b.*$', re.I
)

def canon(token: str) -> str:
    t = re.sub(r'\s+', ' ', token.strip())
    if re.fullmatch(r'(?i)TLS\s*1', t) or re.fullmatch(r'(?i)TLS1', t):
        return 'TLS1.0'
    MAP = {
        'SSLv2': 'SSLv2', 'SSLv3': 'SSLv3',
        'TLS 1.0': 'TLS1.0', 'TLSv1.0': 'TLS1.0',
        'TLS 1.1': 'TLS1.1', 'TLSv1.1': 'TLS1.1',
        'TLS 1.2': 'TLS1.2', 'TLSv1.2': 'TLS1.2',
        'TLS 1.3': 'TLS1.3', 'TLSv1.3': 'TLS1.3',
    }
    return MAP.get(t, t)

NEG = ("not offered", " no", "disabled", "closed", "forbidden", "denied")
POS = ("offered", "enabled", "supported", "accept", "open", "negotiated", " yes")

def run_testssl(testssl_path, target, timeout):
    if os.path.isfile(testssl_path):
        try:
            os.chmod(testssl_path, 0o755)
        except Exception:
            pass
    env = os.environ.copy()
    env["COLOR"] = "0"
    env["WARNINGS"] = "batch"
    env["FAST"] = "true"
    p = subprocess.run(
        ["bash", testssl_path, "-p", target],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=timeout, env=env
    )
    return p.stdout + "\n" + p.stderr

def parse_protocols(raw_text):
    text = clean_text(raw_text)
    res = {k: False for k in ALL_COLS}
    for line in text.splitlines():
        m = PROTO_LABEL_RE.match(line)
        if not m:
            continue
        token = canon(m.group(1))
        if token not in res:
            continue
        low = line.lower()
        if any(k in low for k in NEG):
            val = False
        elif any(k in low for k in POS):
            val = True
        else:
            if "offered" in low and "not offered" not in low:
                val = True
            else:
                continue
        res[token] = val
    return res

def scan_one(target, testssl_path, timeout, dump_dir=None):
    try:
        raw = run_testssl(testssl_path, target, timeout)
        if dump_dir:
            try:
                os.makedirs(dump_dir, exist_ok=True)
                safe = re.sub(r'[^A-Za-z0-9._-]', '_', target)
                with open(os.path.join(dump_dir, f"{safe}.log"), "w", encoding="utf-8") as fh:
                    fh.write(raw)
            except Exception:
                pass
        vals = parse_protocols(raw)
        status = "Fail" if any(vals[c] for c in WEAK_COLS) else "Pass"
        return (target, vals, status)
    except subprocess.TimeoutExpired:
        return (target, {k: False for k in ALL_COLS}, "error: timeout")
    except Exception as e:
        return (target, {k: False for k in ALL_COLS}, f"error: {e}")

def main():
    ap = argparse.ArgumentParser(
        description="Bulk parallel SSL/TLS protocol scanner using testssl.sh"
    )
    ap.add_argument("-i","--input", required=True, help="File with hosts (one per line)")
    ap.add_argument("-o","--output", required=True, help="Output CSV path")
    ap.add_argument("--testssl", default="./testssl.sh", help="Path to testssl.sh (default ./testssl.sh)")
    ap.add_argument("--timeout", type=int, default=180, help="Per-host timeout seconds (default 180)")
    ap.add_argument("-w","--workers", type=int, default=12, help="Parallel workers (default 12)")
    ap.add_argument("--raw-dump-dir", help="Optional directory to save raw testssl outputs for troubleshooting")
    args = ap.parse_args()

    if not os.path.isfile(args.testssl):
        sys.exit(f"testssl.sh not found at {args.testssl}")

    with open(args.input, "r", encoding="utf-8") as f:
        targets = [t.strip() for t in f if t.strip() and not t.strip().startswith("#")]

    results = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {ex.submit(scan_one, t, args.testssl, args.timeout, args.raw_dump_dir): t for t in targets}
        with tqdm(total=len(futs), desc="Scanning targets", unit="host") as pbar:
            for fut in as_completed(futs):
                target_name = futs[fut]
                pbar.set_postfix_str(f"Now scanning: {target_name}")
                target, vals, status = fut.result()
                results.append([target] + [str(vals[c]) for c in ALL_COLS] + [status])
                pbar.update(1)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as out:
        w = csv.writer(out)
        w.writerow(["target"] + ALL_COLS + ["status"])
        for row in sorted(results, key=lambda r: r[0]):
            w.writerow(row)

    fail_count = sum(1 for r in results if r[-1] == "Fail")
    print(f"\nFinished. Fail: {fail_count} / Pass: {len(results)-fail_count} / Total: {len(results)} (wrote {args.output})")

if __name__ == "__main__":
    main()
