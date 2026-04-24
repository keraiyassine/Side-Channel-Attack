# Side-Channel Attack Project

This project demonstrates correlation power analysis (CPA) attacks on AES-128 encryption using both simulated and real hardware data.


## Key Features

- **Complete AES-128 implementation** from scratch (matching NIST standards)
- **Arduino power trace capture** with 800 samples per trace
- **Correlation Power Analysis** attack implementation
- **Real and simulated datasets** for testing
- **Hardware compatibility** with Arduino Mega

## Quick Start

### . Install Dependencies

```bash
pip install numpy pandas h5py pyserial
```




### . Hardware Setup (Arduino)

#### Hardware Requirements
- Arduino  Mega
- Jumper wires
- Either:
  - 3.3V pin connection (simple mode)
  - 47Ω shunt resistor + 5V supply (advanced mode)

#### Wiring Setup

**Simple Mode (3.3V):**
```
Arduino 3.3V pin → A0 pin
Arduino GND     → Arduino GND (already connected)
```

**Advanced Mode (Shunt Resistor):**
```
External 5V+ → 47Ω resistor → Arduino VCC pin
Arduino VCC → A0 pin
External 5V- → Arduino GND
```

**Trigger Connection:**
```
Arduino Pin 8 → Oscilloscope trigger (optional)
```

#### Upload Arduino Code

1. Open `arduino-imp.c` in Arduino IDE
2. Select your Arduino board
3. Upload the sketch




## Implementation Details

### AES Implementation

Both `AES_128.cpp` and `arduino-imp.c` implement the same AES-128 algorithm:

- **S-Box**: Standard AES substitution table
- **Key Expansion**: 11 round keys from 16-byte master key
- **Transformations**: SubBytes, ShiftRows, MixColumns, AddRoundKey
- **Rounds**: 10 rounds (9 full rounds + 1 final round)

### Power Trace Format

Each trace contains **800 samples** structured as:

- **t0-t149** (150 samples): Pre-encryption baseline
- **t150-t649** (500 samples): During AES operations (main leakage)
- **t650-t799** (150 samples): Post-encryption baseline

### CSV Data Format

```
trace_id, plaintext_hex, ciphertext_hex, 
pt_byte_0, pt_byte_1, ..., pt_byte_15,
ct_byte_0, ct_byte_1, ..., ct_byte_15,
power_t0, power_t1, ..., power_t799
```

### CPA Attack Process

1. **Load traces**: Parse CSV and extract plaintexts/power traces
2. **Preprocess**: Center and normalize power traces
3. **Build model**: Hamming weight leakage model for each key guess
4. **Correlate**: Compute Pearson correlation for all 256 key guesses
5. **Recover**: Select key guess with highest absolute correlation
6. **Repeat**: Process all 16 key bytes independently

## Expected Results

With sufficient traces (1000+), you should recover:

- **Most key bytes correctly** with high correlation (>0.3)
- **Peak correlations** around samples 150-650 (during AES)
- **Verification success** when using known key

Typical correlation values:
- **Correct key**: 0.3-0.8 correlation peak
- **Wrong keys**: <0.2 correlation (random noise)
