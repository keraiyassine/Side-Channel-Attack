
#include <AESLib.h>

#define TRIGGER_PIN  8
#define SHUNT_PIN    A0
#define N_SAMPLES    200

// ── MEASUREMENT MODE ─────────────────────────────────────────────
// Set to 1 to use internal 3.3V pin (no extra hardware needed)
// Set to 0 to use external shunt resistor on VCC
#define USE_3V3_MODE 1
// ─────────────────────────────────────────────────────────────────

AESLib aesLib;

byte key[16] = {
  0x2b, 0x7e, 0x15, 0x16,
  0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88,
  0x09, 0xcf, 0x4f, 0x3c
};

byte iv[16];
byte plaintext[16];
byte ciphertext[16];
uint16_t power_samples[N_SAMPLES];

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

void resetIV() {
  memset(iv, 0x00, 16);
}

void setup() {
  pinMode(TRIGGER_PIN, OUTPUT);
  digitalWrite(TRIGGER_PIN, LOW);

  // Speed up ADC: prescaler 16 -> ~77kSPS on Mega
  ADCSRA = (ADCSRA & ~0x07) | 0x04;

  Serial.begin(115200);
  while (!Serial);

  bool stable = checkA0Stable();

  if (!stable) {
    Serial.println("Fix the wiring then press RESET button.");
    while (true) { delay(1000); }
  }

  Serial.println("READY");
}

void loop() {
  if (Serial.available() >= 16) {

    for (int i = 0; i < 16; i++) {
      plaintext[i] = Serial.read();
    }
    memcpy(ciphertext, plaintext, 16);
    resetIV();

    digitalWrite(TRIGGER_PIN, HIGH);

    int s = 0;

    // Pre-encryption baseline samples
    while (s < N_SAMPLES / 4) {
      power_samples[s++] = analogRead(SHUNT_PIN);
    }

    // Encrypt
    aesLib.encrypt(ciphertext, 16, ciphertext, key, 128, iv);

    // Post-encryption samples
    while (s < N_SAMPLES) {
      power_samples[s++] = analogRead(SHUNT_PIN);
    }

    digitalWrite(TRIGGER_PIN, LOW);

    // Send ciphertext (16 bytes)
    Serial.write(ciphertext, 16);

    // Send power samples as raw 16-bit values (2 bytes each)
    for (int i = 0; i < N_SAMPLES; i++) {
      Serial.write((uint8_t)(power_samples[i] >> 8));
      Serial.write((uint8_t)(power_samples[i] & 0xFF));
    }
  }
}
