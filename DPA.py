import argparse
from dataclasses import dataclass
import numpy as np
import pandas as pd

# Import shared utilities and constants from CPA.py
try:
    from CPA import SBOX, load_traces, key_to_hex_string, parse_known_key
except ImportError:
    # Fallback/Redefinition if import fails or for self-containment
    SBOX = np.array(
        [
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
        ],
        dtype=np.uint8,
    )
    def load_traces(csv_path: str): # Simplified version if import fails
        df = pd.read_csv(csv_path)
        pt_cols = [f"pt_byte_{i}" for i in range(16)]
        power_cols = [col for col in df.columns if col.startswith("power_t")]
        plaintexts = df[pt_cols].apply(lambda col: col.map(lambda x: int(str(x), 16))).to_numpy(dtype=np.uint8)
        traces = df[power_cols].to_numpy(dtype=np.float64)
        return plaintexts, traces
    def key_to_hex_string(key_bytes):
        return " ".join(f"{b:02X}" for b in key_bytes)
    def parse_known_key(known_key_hex):
        cleaned = known_key_hex.replace("0x", "").replace(" ", "")
        return [int(cleaned[i : i + 2], 16) for i in range(0, 32, 2)]

@dataclass
class ByteDPAResult:
    byte_index: int
    best_key_guess: int
    best_peak_dom: float
    best_peak_sample: int
    selection_bit: int


def selection_function(pt_byte_values: np.ndarray, key_guess: int, bit: int) -> np.ndarray:
    """
    Step 2: Selection function.
    Returns a boolean array: True if the target bit of SBOX(pt XOR kg) is 1.
    """
    sbox_out = SBOX[np.bitwise_xor(pt_byte_values, key_guess)]
    return ((sbox_out >> bit) & 1).astype(bool)


def partition_traces(traces: np.ndarray, selection: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """
    Step 3: Partition traces into two groups based on the selection bit.
    """
    group1 = traces[selection]
    group0 = traces[~selection]
    return group0, group1


def difference_of_means(group0: np.ndarray, group1: np.ndarray) -> np.ndarray:
    """
    Step 4: Compute the Difference of Means (DoM).
    """
    if len(group1) == 0 or len(group0) == 0:
        return np.zeros(group0.shape[1] if len(group0) > 0 else group1.shape[1])
    
    return group1.mean(axis=0) - group0.mean(axis=0)


def score_key_guess_dpa(
    pt_byte_values: np.ndarray,
    key_guess: int,
    traces: np.ndarray,
    bit: int,
) -> tuple[float, int]:
    """
    Step 5: Score one key guess using DPA.
    Score = max absolute difference of means across all samples.
    """
    selection = selection_function(pt_byte_values, key_guess, bit)
    group0, group1 = partition_traces(traces, selection)
    
    # Need at least some traces in each group to be statistically meaningful
    if len(group0) < 2 or len(group1) < 2:
        return 0.0, 0
    
    diff_trace = difference_of_means(group0, group1)
    peak_sample = int(np.argmax(np.abs(diff_trace)))
    peak_dom = float(np.abs(diff_trace[peak_sample]))
    return peak_dom, peak_sample


def run_dpa_for_one_byte(
    pt_byte_values: np.ndarray,
    traces: np.ndarray,
    byte_index: int,
    bit: int = 0,
) -> ByteDPAResult:
    """
    Step 6: Try all 256 key guesses for one byte.
    """
    best_guess = 0
    best_peak_dom = -1.0
    best_peak_sample = 0

    for guess in range(256):
        peak_dom, peak_sample = score_key_guess_dpa(
            pt_byte_values=pt_byte_values,
            key_guess=guess,
            traces=traces,
            bit=bit,
        )

        if peak_dom > best_peak_dom:
            best_guess = guess
            best_peak_dom = peak_dom
            best_peak_sample = peak_sample

    return ByteDPAResult(
        byte_index=byte_index,
        best_key_guess=best_guess,
        best_peak_dom=best_peak_dom,
        best_peak_sample=best_peak_sample,
        selection_bit=bit,
    )


def run_dpa_all_bytes(
    plaintexts: np.ndarray, 
    traces: np.ndarray, 
    bit: int = 0
) -> list[ByteDPAResult]:
    """
    Step 7: Attack all 16 bytes.
    """
    results: list[ByteDPAResult] = []
    for byte_index in range(16):
        pt_byte_values = plaintexts[:, byte_index]
        result = run_dpa_for_one_byte(
            pt_byte_values=pt_byte_values,
            traces=traces,
            byte_index=byte_index,
            bit=bit,
        )
        print(f"  Byte {byte_index:02d} recovered: {result.best_key_guess:02X} (peak DoM: {result.best_peak_dom:.6f})")
        results.append(result)

    return results


def print_results_dpa(results: list[ByteDPAResult], known_key_hex: str | None = None) -> None:
    """
    Step 8: Display results.
    """
    recovered_key = [r.best_key_guess for r in results]

    print("\nRecovered key bytes (DPA):")
    for r in results:
        print(
            f"byte {r.byte_index:02d}: {r.best_key_guess:02X}  "
            f"|peak DoM|={r.best_peak_dom:.6f}  @sample={r.best_peak_sample}"
        )

    print(f"\nRecovered key: {key_to_hex_string(recovered_key)}")

    if known_key_hex is not None:
        known_key = parse_known_key(known_key_hex)
        matches = sum(1 for a, b in zip(recovered_key, known_key) if a == b)
        print(f"Known key    : {key_to_hex_string(known_key)}")
        print(f"Byte matches : {matches}/16")


def main() -> None:
    parser = argparse.ArgumentParser(description="Differential Power Analysis (DPA) for AES-128")
    parser.add_argument("--csv", default="traces.csv", help="Path to CSV trace file")
    parser.add_argument("--bit", type=int, default=0, help="Selection bit (0-7, default 0)")
    parser.add_argument(
        "--known-key",
        default=None,
        help="Optional 16-byte key for verification (spaces allowed)",
    )
    args = parser.parse_args()

    print(f"[*] Loading traces from {args.csv}...")
    try:
        plaintexts, traces = load_traces(args.csv)
    except Exception as e:
        print(f"[!] Error loading traces: {e}")
        return

    print(f"[*] Traces: {plaintexts.shape[0]}, Samples: {traces.shape[1]}")
    print(f"[*] Selection bit: {args.bit}")
    
    if plaintexts.shape[0] < 500:
        print("[!] Warning: DPA usually requires more traces (e.g. >1000) to be successful.")

    print("[*] Starting DPA attack...")
    results = run_dpa_all_bytes(plaintexts, traces, bit=args.bit)
    print_results_dpa(results, known_key_hex=args.known_key)


if __name__ == "__main__":
    main()
