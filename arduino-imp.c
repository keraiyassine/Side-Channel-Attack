
#include <Arduino.h>

#define TRIGGER_PIN  8
#define SHUNT_PIN    A0
#define N_SAMPLES    800  // Match project standard: 800 samples per trace

// ── MEASUREMENT MODE ─────────────────────────────────────────────
// Set to 1 to use internal 3.3V pin (no extra hardware needed)
// Set to 0 to use external shunt resistor on VCC
#define USE_3V3_MODE 1
// ─────────────────────────────────────────────────────────────────

// AES S-Box (same as AES_128.cpp)
const uint8_t SBOX[256] = {
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
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// Round constants
const uint8_t RCON[10] = {
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// Project standard key (same as AES_128.cpp)
uint8_t key[16] = {
  0x2b, 0x7e, 0x15, 0x16,
  0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88,
  0x09, 0xcf, 0x4f, 0x3c
};

uint8_t plaintext[16];
uint8_t ciphertext[16];
uint8_t roundKeys[11][16];  // 11 round keys
uint16_t power_samples[N_SAMPLES];

// ── AES IMPLEMENTATION (matching AES_128.cpp) ───────────────────────

uint8_t xtime(uint8_t x) {
  return ((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
}

void addRoundKey(uint8_t *state, const uint8_t *roundKey) {
  for (int i = 0; i < 16; i++) {
    state[i] ^= roundKey[i];
  }
}

void subBytes(uint8_t *state) {
  for (int i = 0; i < 16; i++) {
    state[i] = SBOX[state[i]];
  }
}

void shiftRows(uint8_t *state) {
  uint8_t temp = state[1];
  state[1] = state[5];
  state[5] = state[9];
  state[9] = state[13];
  state[13] = temp;

  temp = state[2];
  state[2] = state[10];
  state[10] = temp;

  temp = state[6];
  state[6] = state[14];
  state[14] = temp;

  temp = state[3];
  state[3] = state[15];
  state[15] = state[11];
  state[11] = state[7];
  state[7] = temp;
}

void mixColumns(uint8_t *state) {
  uint8_t tmp[16];
  
  for (int col = 0; col < 4; col++) {
    uint8_t s0 = state[0 + col];
    uint8_t s1 = state[4 + col];
    uint8_t s2 = state[8 + col];
    uint8_t s3 = state[12 + col];

    tmp[0 + col] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3;
    tmp[4 + col] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3;
    tmp[8 + col] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3);
    tmp[12 + col] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3);
  }
  
  for (int i = 0; i < 16; i++) {
    state[i] = tmp[i];
  }
}

void expandKey() {
  // Copy original key as first round key
  for (int i = 0; i < 16; i++) {
    roundKeys[0][i] = key[i];
  }
  
  for (int round = 1; round <= 10; round++) {
    uint8_t temp[4];
    
    // Get last word of previous round key
    for (int i = 0; i < 4; i++) {
      temp[i] = roundKeys[round - 1][12 + i];
    }
    
    // RotWord
    uint8_t t = temp[0];
    temp[0] = temp[1];
    temp[1] = temp[2];
    temp[2] = temp[3];
    temp[3] = t;
    
    // SubWord
    for (int i = 0; i < 4; i++) {
      temp[i] = SBOX[temp[i]];
    }
    
    // XOR with Rcon
    temp[0] ^= RCON[round - 1];
    
    // Generate new round key
    for (int i = 0; i < 4; i++) {
      // First word
      roundKeys[round][i] = roundKeys[round - 1][i] ^ temp[i];
      // Remaining words
      roundKeys[round][4 + i] = roundKeys[round - 1][4 + i] ^ roundKeys[round][i];
      roundKeys[round][8 + i] = roundKeys[round - 1][8 + i] ^ roundKeys[round][4 + i];
      roundKeys[round][12 + i] = roundKeys[round - 1][12 + i] ^ roundKeys[round][8 + i];
    }
  }
}

void AES128_encrypt(const uint8_t *plaintext, uint8_t *ciphertext) {
  // Copy plaintext to state
  for (int i = 0; i < 16; i++) {
    ciphertext[i] = plaintext[i];
  }
  
  // Initial round key addition
  addRoundKey(ciphertext, roundKeys[0]);
  
  // 9 main rounds
  for (int round = 1; round <= 9; round++) {
    subBytes(ciphertext);
    shiftRows(ciphertext);
    mixColumns(ciphertext);
    addRoundKey(ciphertext, roundKeys[round]);
  }
  
  // Final round (no MixColumns)
  subBytes(ciphertext);
  shiftRows(ciphertext);
  addRoundKey(ciphertext, roundKeys[10]);
}

// ── A0 STABILITY CHECK ───────────────────────────────────────────
bool checkA0Stable() {
  Serial.println("----------------------------------");

#if USE_3V3_MODE
  Serial.println("MODE: 3.3V internal pin -> A0");
  Serial.println("No external supply needed.");
  float expected_min = 2.8;
  float expected_max = 3.6;
#else
  Serial.println("MODE: External shunt resistor on VCC");
  float expected_min = 4.0;
  float expected_max = 5.1;
#endif

  Serial.println("A0 STABILITY CHECK - please wait 3 seconds...");

  const int CHECK_SAMPLES = 300;
  float readings[CHECK_SAMPLES];
  float sum = 0;
  int bad_low  = 0;
  int bad_high = 0;

  for (int i = 0; i < CHECK_SAMPLES; i++) {
    float v = analogRead(SHUNT_PIN) * (5.0 / 1023.0);
    readings[i] = v;
    sum += v;
    if (v < expected_min) bad_low++;
    if (v > expected_max) bad_high++;
    delay(10);
  }

  float avg = sum / CHECK_SAMPLES;

  float variance = 0;
  for (int i = 0; i < CHECK_SAMPLES; i++) {
    float diff = readings[i] - avg;
    variance += diff * diff;
  }
  float stddev = sqrt(variance / CHECK_SAMPLES);

  Serial.print("  Average voltage : "); Serial.print(avg, 3);   Serial.println("V");
  Serial.print("  Std deviation   : "); Serial.print(stddev, 4); Serial.println("V");
  Serial.print("  Samples out of range : "); Serial.print(bad_low + bad_high);
  Serial.print(" / "); Serial.println(CHECK_SAMPLES);

  bool ok = true;

  if (avg < expected_min) {
#if USE_3V3_MODE
    Serial.println("  [FAIL] Average too low.");
    Serial.println("         Check wire from 3.3V pin to A0.");
#else
    Serial.println("  [FAIL] Average too low.");
    Serial.println("         Check external 5V supply and 47 ohm shunt.");
#endif
    ok = false;
  }

  if (bad_low > 5) {
#if USE_3V3_MODE
    Serial.println("  [FAIL] Too many low-voltage spikes.");
    Serial.println("         3.3V to A0 wire is loose.");
#else
    Serial.println("  [FAIL] Too many low-voltage spikes.");
    Serial.println("         A0 wire is loose - press jumper firmly.");
#endif
    ok = false;
  }

  if (bad_high > 5) {
    Serial.println("  [FAIL] Too many high-voltage spikes.");
    Serial.println("         A0 is floating - check wire connection.");
    ok = false;
  }

  if (stddev > 0.15) {
    Serial.println("  [FAIL] Voltage unstable (stddev > 0.15V).");
    Serial.println("         Add 10uF capacitor between A0 and GND.");
    ok = false;
  }

  if (ok) {
#if USE_3V3_MODE
    Serial.println("  [PASS] 3.3V mode stable - ready to capture.");
#else
    Serial.println("  [PASS] Shunt mode stable - ready to capture.");
#endif
  }

  Serial.println("----------------------------------");
  return ok;
}
// ─────────────────────────────────────────────────────────────────

void setup() {
  pinMode(TRIGGER_PIN, OUTPUT);
  digitalWrite(TRIGGER_PIN, LOW);

  // Speed up ADC: prescaler 16 -> ~77kSPS on Mega
  ADCSRA = (ADCSRA & ~0x07) | 0x04;

  Serial.begin(115200);
  while (!Serial);

  // Initialize AES round keys
  expandKey();

  bool stable = checkA0Stable();

  if (!stable) {
    Serial.println("Fix the wiring then press RESET button.");
    while (true) { delay(1000); }
  }

  Serial.println("READY");
}

void loop() {
  if (Serial.available() >= 16) {

    // Read 16-byte plaintext
    for (int i = 0; i < 16; i++) {
      plaintext[i] = Serial.read();
    }

    digitalWrite(TRIGGER_PIN, HIGH);

    int s = 0;

    // Pre-encryption baseline samples (150 samples)
    // Matches project format: t0-t149 = pre-encryption
    while (s < 150) {
      power_samples[s++] = analogRead(SHUNT_PIN);
    }

    // Encrypt with our manual AES implementation
    AES128_encrypt(plaintext, ciphertext);

    // During AES samples (500 samples)  
    // Matches project format: t150-t649 = during AES
    while (s < 650) {
      power_samples[s++] = analogRead(SHUNT_PIN);
    }

    // Post-encryption baseline samples (150 samples)
    // Matches project format: t650-t799 = post-encryption
    while (s < 800) {
      power_samples[s++] = analogRead(SHUNT_PIN);
    }

    digitalWrite(TRIGGER_PIN, LOW);

    // Send plaintext first (for trace verification)
    Serial.write(plaintext, 16);
    
    // Send ciphertext (16 bytes)
    Serial.write(ciphertext, 16);

    // Send power samples as raw 16-bit values (2 bytes each)
    // Total: 800 samples * 2 bytes = 1600 bytes
    for (int i = 0; i < N_SAMPLES; i++) {
      Serial.write((uint8_t)(power_samples[i] >> 8));
      Serial.write((uint8_t)(power_samples[i] & 0xFF));
    }
  }
}
