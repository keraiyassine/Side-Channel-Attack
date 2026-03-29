import argparse
from dataclasses import dataclass

import numpy as np
import pandas as pd


# AES S-box used in SubBytes.
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

# HW_TABLE[x] gives the Hamming Weight of byte x (0..255).
HW_TABLE = np.array([bin(x).count("1") for x in range(256)], dtype=np.uint8)


@dataclass
class ByteCPAResult:
    byte_index: int
    best_key_guess: int
    best_peak_corr: float
    best_peak_sample: int


def parse_hex_byte(text: str) -> int:
    """Convert a string like '0x2B' into integer 43."""
    return int(str(text).strip(), 16)


def load_traces(csv_path: str) -> tuple[np.ndarray, np.ndarray]:
    """
    Step 1: Load plaintext bytes and power traces from CSV.

    Returns:
    - plaintexts: shape (num_traces, 16), dtype uint8
    - traces: shape (num_traces, num_samples), dtype float64
    """
    df = pd.read_csv(csv_path)

    pt_cols = [f"pt_byte_{i}" for i in range(16)]
    power_cols = [col for col in df.columns if col.startswith("power_t")]

    missing = [c for c in pt_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Missing plaintext columns: {missing}")

    if not power_cols:
        raise ValueError("No power_t* columns found in CSV.")

    plaintext_df = df[pt_cols].apply(lambda col: col.map(parse_hex_byte))
    plaintexts = plaintext_df.to_numpy(dtype=np.uint8)
    traces = df[power_cols].to_numpy(dtype=np.float64)

    return plaintexts, traces


def center_and_norm_traces(traces: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """
    Step 2: Precompute centered traces and their per-sample norms.

    This lets correlation be computed efficiently for many key guesses.
    """
    traces_centered = traces - traces.mean(axis=0)
     # since new mean is 0 then traces_norm here is standard deviation of the traces vector
    traces_norm = np.linalg.norm(traces_centered, axis=0)
    return traces_centered, traces_norm


def predict_leakage_hw(pt_byte_values: np.ndarray, key_guess: int) -> np.ndarray:
    """
    Step 3: Build leakage model for one byte and one key guess.

    Model: L_i = HW(SBOX(P_i XOR key_guess))
    """
    sbox_output = SBOX[np.bitwise_xor(pt_byte_values, key_guess)]
    leakage = HW_TABLE[sbox_output].astype(np.float64)
    return leakage


def pearson_against_all_samples(
    leakage_model: np.ndarray,
    traces_centered: np.ndarray,
    traces_norm: np.ndarray,
) -> np.ndarray:
    """
    Step 4: Correlate one model vector against every trace sample column.

    Returns correlation vector rho[j] for j=0..num_samples-1.
    """
    model_centered = leakage_model - leakage_model.mean()
    # since new mean is 0 then model_norm here is standard deviation of the model vector
    model_norm = np.linalg.norm(model_centered)

    if model_norm == 0:
        return np.zeros(traces_centered.shape[1], dtype=np.float64)

    # Dot product of the centered leakage model with each trace sample column.
    # Result shape is (num_samples,), i.e., Pearson numerators for all samples.
    numerators = model_centered @ traces_centered
    denominators = model_norm * traces_norm

    corr = np.divide(
        numerators,
        denominators,
        # Pre-fill output with zeros so any unsafe division (where denominator==0)
        # keeps a safe 0.0 correlation instead of inf/nan.
        out=np.zeros_like(numerators, dtype=np.float64),
        where=denominators != 0,
    )
    return corr


def score_key_guess(
    pt_byte_values: np.ndarray,
    key_guess: int,
    traces_centered: np.ndarray,
    traces_norm: np.ndarray,
) -> tuple[float, int]:
    """
    Step 5: Score one key guess.

    Score = max absolute correlation over all sample points.
    """
    leakage = predict_leakage_hw(pt_byte_values, key_guess)
    corr_curve = pearson_against_all_samples(leakage, traces_centered, traces_norm)

    peak_sample = int(np.argmax(np.abs(corr_curve)))
    peak_corr = float(abs(corr_curve[peak_sample]))
    return peak_corr, peak_sample


def run_cpa_for_one_byte(
    pt_byte_values: np.ndarray,
    traces_centered: np.ndarray,
    traces_norm: np.ndarray,
    byte_index: int,
) -> ByteCPAResult:
    """
    Step 6: Try all 256 key guesses for one AES byte position.

    Keep the guess with highest |correlation| peak.
    """
    best_guess = 0
    best_peak_corr = -1.0
    best_peak_sample = 0

    for guess in range(256):
        peak_corr, peak_sample = score_key_guess(
            pt_byte_values=pt_byte_values,
            key_guess=guess,
            traces_centered=traces_centered,
            traces_norm=traces_norm,
        )

        if peak_corr > best_peak_corr:
            best_guess = guess
            best_peak_corr = peak_corr
            best_peak_sample = peak_sample

    return ByteCPAResult(
        byte_index=byte_index,
        best_key_guess=best_guess,
        best_peak_corr=best_peak_corr,
        best_peak_sample=best_peak_sample,
    )


def run_cpa_all_bytes(plaintexts: np.ndarray, traces: np.ndarray) -> list[ByteCPAResult]:
    """
    Step 7: Attack all 16 key bytes independently.
    """
    traces_centered, traces_norm = center_and_norm_traces(traces)

    results: list[ByteCPAResult] = []
    for byte_index in range(16):
        pt_byte_values = plaintexts[:, byte_index]
        result = run_cpa_for_one_byte(
            pt_byte_values=pt_byte_values,
            traces_centered=traces_centered,
            traces_norm=traces_norm,
            byte_index=byte_index,
        )
        results.append(result)

    return results


def key_to_hex_string(key_bytes: list[int]) -> str:
    return " ".join(f"{b:02X}" for b in key_bytes)


def parse_known_key(known_key_hex: str) -> list[int]:
    """Parse key text such as '2B 7E 15 ...' into list of 16 integers."""
    cleaned = known_key_hex.replace("0x", "").replace(" ", "")
    if len(cleaned) != 32:
        raise ValueError("Known key must be 16 bytes (32 hex chars).")
    return [int(cleaned[i : i + 2], 16) for i in range(0, 32, 2)]


def print_results(results: list[ByteCPAResult], known_key_hex: str | None = None) -> None:
    """Step 8: Display recovered key and optional comparison with known key."""
    recovered_key = [r.best_key_guess for r in results]

    print("\nRecovered key bytes (CPA):")
    for r in results:
        print(
            f"byte {r.byte_index:02d}: {r.best_key_guess:02X}  "
            f"|peak corr|={r.best_peak_corr:.6f}  @sample={r.best_peak_sample}"
        )

    print(f"\nRecovered key: {key_to_hex_string(recovered_key)}")

    if known_key_hex is not None:
        known_key = parse_known_key(known_key_hex)
        matches = sum(1 for a, b in zip(recovered_key, known_key) if a == b)
        print(f"Known key    : {key_to_hex_string(known_key)}")
        print(f"Byte matches : {matches}/16")


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple step-by-step CPA for AES-128")
    parser.add_argument("--csv", default="traces.csv", help="Path to CSV trace file")
    parser.add_argument(
        "--known-key",
        default=None,
        help="Optional 16-byte key for verification (spaces allowed)",
    )
    args = parser.parse_args()

    plaintexts, traces = load_traces(args.csv)
    print(f"Loaded traces: {plaintexts.shape[0]}")
    print(f"Samples per trace: {traces.shape[1]}")

    results = run_cpa_all_bytes(plaintexts, traces)
    print_results(results, known_key_hex=args.known_key)


if __name__ == "__main__":
    main()
