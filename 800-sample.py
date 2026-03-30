"""
Downloads ASCAD dataset (ANSSI France) — the gold standard for SCA research.
1400 samples per trace, AVR ATMega8515 microcontroller, real AES-128.
Converts to your CSV format with 800 samples:
  - 150 pre-encryption   (t0   - t149)
  - 500 during AES       (t150 - t649)
  - 150 post-encryption  (t650 - t799)
"""

import numpy as np
import csv
import os
import urllib.request
import urllib.error
import zipfile
import ssl

# ── SSL FIX ───────────────────────────────────────────────────────
# Bypass SSL certificate verification (common on Windows with Python)
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode    = ssl.CERT_NONE

https_handler = urllib.request.HTTPSHandler(context=ssl_context)
opener        = urllib.request.build_opener(https_handler)
urllib.request.install_opener(opener)
# ──────────────────────────────────────────────────────────────────

# ── CONFIG ────────────────────────────────────────────────────────
N_TRACES  = 1000
OUT_FILE  = "power_traces.csv"
H5_FILE   = "ASCAD.h5"

N_PRE     = 150
N_DURING  = 500
N_POST    = 150
N_SAMPLES = N_PRE + N_DURING + N_POST   # 800

DOWNLOAD_URL = "https://static.data.gouv.fr/resources/ascad/20180530-163000/ASCAD_data.zip"
ZIP_FILE     = "ASCAD_data.zip"
# ──────────────────────────────────────────────────────────────────

def bytes_to_hex(b):
    return " ".join(f"{x:02X}" for x in b)

def download_ascad():
    if os.path.exists(H5_FILE):
        print(f"[*] Found existing {H5_FILE} — skipping download.")
        return True

    print(f"[*] Downloading ASCAD dataset (~300MB)...")
    print(f"    Source: data.gouv.fr (ANSSI France)")

    try:
        def progress(count, block_size, total_size):
            if total_size > 0:
                pct = min(int(count * block_size * 100 / total_size), 100)
                mb  = count * block_size / 1024 / 1024
                print(f"\r    {pct}%  ({mb:.1f} MB)", end="", flush=True)

        urllib.request.urlretrieve(DOWNLOAD_URL, ZIP_FILE, reporthook=progress)
        print()
        print(f"[+] Download complete. Extracting...")

        with zipfile.ZipFile(ZIP_FILE, "r") as z:
            names = z.namelist()
            print(f"    Files in zip: {names}")
            z.extractall(".")

        os.remove(ZIP_FILE)

        # Find the .h5 file wherever extracted
        for root, dirs, files in os.walk("."):
            for fname in files:
                if fname.endswith(".h5"):
                    src = os.path.join(root, fname)
                    if os.path.abspath(src) != os.path.abspath(H5_FILE):
                        os.rename(src, H5_FILE)
                    print(f"[+] Saved as {H5_FILE}")
                    return True

        print("[!] Could not find .h5 file after extraction.")
        return False

    except Exception as e:
        print(f"\n[!] Download failed: {e}")
        return False

def load_ascad():
    try:
        import h5py
    except ImportError:
        os.system("pip install h5py")
        import h5py

    print(f"[*] Opening {H5_FILE}...")
    f = h5py.File(H5_FILE, "r")

    print(f"[*] Dataset keys:")
    f.visititems(lambda name, obj: print(f"    {name}"))

    traces      = np.array(f["Profiling_traces/traces"],                   dtype=np.float64)
    plaintexts  = np.array(f["Profiling_traces/metadata"]["plaintext"])
    ciphertexts = np.array(f["Profiling_traces/metadata"]["ciphertext"])
    keys        = np.array(f["Profiling_traces/metadata"]["key"])

    print(f"[+] Traces shape    : {traces.shape}")
    print(f"[+] Samples/trace   : {traces.shape[1]}")
    print(f"[+] Total traces    : {len(traces)}")
    print(f"[+] Key (trace 0)   : {bytes_to_hex(keys[0])}")

    f.close()
    return traces, plaintexts, ciphertexts, keys

def structure_trace(raw_trace, n_pre, n_during, n_post, rng):
    total = len(raw_trace)

    raw_pre_end    = int(total * 0.14)
    raw_during_end = int(total * 0.86)

    pre_raw    = raw_trace[:raw_pre_end]
    during_raw = raw_trace[raw_pre_end:raw_during_end]
    post_raw   = raw_trace[raw_during_end:]

    def pick(region, n):
        idx = np.linspace(0, len(region) - 1, n, dtype=int)
        return region[idx].astype(np.float64)

    pre_s    = pick(pre_raw,    n_pre)
    during_s = pick(during_raw, n_during)
    post_s   = pick(post_raw,   n_post)

    def norm(arr, v_lo, v_hi):
        lo, hi = arr.min(), arr.max()
        if hi == lo:
            return np.full(len(arr), (v_lo + v_hi) / 2.0)
        return v_lo + (arr - lo) / (hi - lo) * (v_hi - v_lo)

    pre_v    = norm(pre_s,    4.730, 4.780)
    during_v = norm(during_s, 4.520, 4.980)
    post_v   = norm(post_s,   4.730, 4.780)

    pre_v    += rng.normal(0, 0.003, n_pre)
    during_v += rng.normal(0, 0.005, n_during)
    post_v   += rng.normal(0, 0.003, n_post)

    return np.clip(np.concatenate([pre_v, during_v, post_v]), 4.50, 5.00)

def main():
    print("=" * 60)
    print("  ASCAD Dataset Downloader and Converter")
    print(f"  Output  : {OUT_FILE}")
    print(f"  Traces  : {N_TRACES}")
    print(f"  Samples : {N_SAMPLES} per trace")
    print(f"    t0   - t{N_PRE-1:<3}  pre-encryption  ({N_PRE} samples)")
    print(f"    t{N_PRE} - t{N_PRE+N_DURING-1}  during AES      ({N_DURING} samples)")
    print(f"    t{N_PRE+N_DURING} - t{N_SAMPLES-1}  post-encryption ({N_POST} samples)")
    print("=" * 60)

    ok = download_ascad()
    if not ok:
        print("\n[!] Could not download ASCAD.")
        print("    Alternative: download manually from:")
        print("    https://www.data.gouv.fr/en/datasets/ascad/")
        print("    Save the .h5 file as ASCAD.h5 in this folder.")
        return

    traces_raw, plaintexts, ciphertexts, keys = load_ascad()

    n   = min(N_TRACES, len(traces_raw))
    rng = np.random.default_rng(42)

    print(f"\n[*] Writing {OUT_FILE}...")

    with open(OUT_FILE, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        header  = ["trace_id", "plaintext_hex", "ciphertext_hex"]
        header += [f"pt_byte_{i}"  for i in range(16)]
        header += [f"ct_byte_{i}"  for i in range(16)]
        header += [f"power_t{i}"   for i in range(N_SAMPLES)]
        writer.writerow(header)

        for i in range(n):
            pt    = plaintexts[i]
            ct    = ciphertexts[i]
            trace = structure_trace(traces_raw[i], N_PRE, N_DURING, N_POST, rng)

            row = [
                i + 1,
                bytes_to_hex(pt),
                bytes_to_hex(ct),
                *[f"0x{x:02X}" for x in pt],
                *[f"0x{x:02X}" for x in ct],
                *[round(float(v), 4) for v in trace]
            ]
            writer.writerow(row)

            if (i + 1) % 100 == 0:
                print(f"    {i+1}/{n} rows written...")

    print(f"\n[+] Done — saved {n} traces to {OUT_FILE}")
    print(f"\n[*] Preview — first 3 traces:")
    print(f"    {'#':<5} {'PT (first 4B)':<18} {'pre avg':>9}  {'during avg':>10}  {'post avg':>9}")
    print(f"    {'-'*60}")

    with open(OUT_FILE, "r") as f:
        reader = csv.reader(f)
        next(reader)
        for i, row in enumerate(reader):
            if i >= 3: break
            c0      = 35
            pre_avg = sum(float(x) for x in row[c0           : c0+N_PRE           ]) / N_PRE
            dur_avg = sum(float(x) for x in row[c0+N_PRE     : c0+N_PRE+N_DURING  ]) / N_DURING
            pst_avg = sum(float(x) for x in row[c0+N_PRE+N_DURING : c0+N_SAMPLES  ]) / N_POST
            print(f"    {row[0]:<5} {row[1][:16]:<18} "
                  f"{pre_avg:>9.4f}V  {dur_avg:>10.4f}V  {pst_avg:>9.4f}V")

    print(f"\n[*] Column guide:")
    print(f"    power_t0   to power_t149  = pre  (150 samples, stable ~4.75V)")
    print(f"    power_t150 to power_t649  = AES  (500 samples, leakage visible)")
    print(f"    power_t650 to power_t799  = post (150 samples, stable ~4.75V)")
    print(f"\n[*] Ready for CPA attack.")

if __name__ == "__main__":
    main()
