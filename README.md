# Side-Channel Attack: DPA and CPA on AES-128

This project demonstrates both **Differential Power Analysis (DPA)** and **Correlation Power Analysis (CPA)** attacks targeting an AES-128 implementation. It bridges the gap between hardware data acquisition (Arduino) and cryptographic cryptanalysis (Python), showing how physical power measurements leak secret key information.

## Overview

A Side-Channel Attack exploits information leaked by the physical implementation of a cryptosystem. In this project, we implement two primary power analysis techniques against the first execution round of AES:

1. **Correlation Power Analysis (CPA):** Targets the **Hamming Weight** of the AES S-Box output. We construct a multi-bit leakage model and compute the **Pearson Correlation Coefficient** against measured traces.
2. **Differential Power Analysis (DPA):** Targets a single **selection bit** of the S-Box output. Traces are partitioned into two sets, and we compute the **Difference of Means (DoM)** to isolate the secret key.

## Project Structure

- "CPA.py" - Core CPA script performing fast vectorized Pearson correlation using a Hamming weight leakage model.
- "DPA.py" - Core DPA script utilizing statistical Difference of Means (DoM) based on single-bit partitioning.
- "AES_128.cpp" / "arduino-imp.c" - The target AES-128 implementations in C++.
- Data: "dataset/\*.csv" (datasets containing captured plaintexts, ciphertexts, and power measurements).

## Hardware Setup & Data Acquisition

Capturing high-quality power traces is the most critical step of an SCA. Traces were captured from an **Arduino Mega**.

**Crucial Finding during Development:**
Traditional analog read functions ("analogRead()") are too slow and block execution, failing to capture the exact moments AES is executing. To solve this, the Arduino firmware uses a **Free-running ADC with Interrupts ("ISR(ADC_vect)")**. This allows the Arduino to sample its own power consumption simultaneously while computing the AES encryption, resulting in accurate temporal alignment.

- **Sample Window:** 800 samples per encryption.
- **Trigger:** Configured to sample _during_ the execution of the 10 AES rounds.

## Software Implementation

Both "CPA.py" and "DPA.py" are heavily commented.

### CPA Workflow:

1. Imitates the "SubBytes" operation for all 256 key guesses per byte, calculating Hamming Weight.
2. Measures the statistical relationship (Pearson Correlation) between the actual power trace and the theoretical model.
3. Ranks key guesses by highest absolute correlation peak.

### DPA Workflow:

1. Computes the target selection bit of "SubBytes" for all 256 key guesses.
2. Evaluates the Difference of Means (DoM) between "bit=1" traces and "bit=0" traces.
3. Ranks key guesses by the maximum absolute DoM amplitude peak.

## Quick Start

### 1. Install Dependencies

```bash
pip install numpy pandas tqdm
```

### 2. Run the Attacks

Known test key used in this project:

```
2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C
```

**CPA options**

- `--csv`: Path to the CSV trace file.
- `--n-traces`: (Optional) Number of traces to use from the start of the file.
- `--known-key`: (Optional) 16-byte key in hex (spaces allowed) for verification.

**DPA options**

- `--csv`: Path to the CSV trace file.
- `--bit`: Selection bit (0-7) for the DPA partitioning.
- `--known-key`: (Optional) 16-byte key in hex (spaces allowed) for verification.

Execute the CPA script:

```bash
python CPA.py --csv dataset/dataset-800samples-10K.csv --n-traces 10000 --known-key "2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C"
```

Execute the DPA script:

```bash
python DPA.py --csv dataset/dataset-800samples-10K.csv --bit 0 --known-key "2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C"
```

### Datasets

All datasets are under the `dataset/` folder.

- `dataset-800samples-10K.csv`: Main dataset (10K traces, 800 samples per trace).
- `dataset-200samples-10K.csv`: Short window dataset (10K traces, 200 samples per trace).
- `dataset_random_delay.csv`: Random delay countermeasure.
- `dataset_dummy_ops.csv`: Dummy operations countermeasure.
- `dataset_shuffling.csv`: Operation shuffling countermeasure.
- `dataset_simple_mask.csv`: Simple masking countermeasure.
- `dataset_boolean_mask.csv`: Boolean masking countermeasure.

### Data Format (".csv")

Traces must be structured with the following columns:

- "trace_id"
- "plaintext_hex"
- "ciphertext_hex"
- "power_t0" ... "power_t799"

## Results

With well-aligned traces, both attacks can successfully extract the 16 bytes of the AES master key.

- **CPA** is generally more efficient and requires fewer traces as it leverages the full Hamming weight leakage.
- **DPA** is a fundamental technique requiring little assumption about the generic leakage model, though it typically requires larger datasets (e.g., >1000 traces).
