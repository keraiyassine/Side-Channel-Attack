#!/usr/bin/env python3
"""
Collect power traces from Arduino and format them for CPA attack.
This script communicates with the Arduino to generate traces in the 
format expected by CPA.py (800 samples per trace).
"""

import serial
import csv
import numpy as np
import argparse
from pathlib import Path
import time

def bytes_to_hex(b):
    return " ".join(f"{x:02X}" for x in b)

def collect_arduino_traces(port: str, num_traces: int, output_file: str):
    """Collect traces from Arduino and save to CSV format."""
    
    try:
        ser = serial.Serial(port, 115200, timeout=10)
        print(f"[+] Connected to Arduino on {port}")
    except serial.SerialException as e:
        print(f"[!] Failed to connect to Arduino: {e}")
        return False
    
    try:
        # Wait for Arduino to be ready
        print("[*] Waiting for Arduino to initialize...")
        while True:
            line = ser.readline().decode('ascii').strip()
            if line == "READY":
                print("[+] Arduino ready")
                break
            elif line:
                print(f"    Arduino: {line}")
    
    except Exception as e:
        print(f"[!] Error reading from Arduino: {e}")
        ser.close()
        return False
    
    # Prepare CSV file
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write header matching CPA.py expectations
        header = ["trace_id", "plaintext_hex", "ciphertext_hex"]
        header += [f"pt_byte_{i}" for i in range(16)]
        header += [f"ct_byte_{i}" for i in range(16)]
        header += [f"power_t{i}" for i in range(800)]
        writer.writerow(header)
        
        print(f"[*] Collecting {num_traces} traces...")
        
        for trace_id in range(1, num_traces + 1):
            try:
                # Generate random plaintext
                plaintext = np.random.randint(0, 256, 16, dtype=np.uint8)
                plaintext_hex = bytes_to_hex(plaintext)
                
                # Send plaintext to Arduino
                ser.write(plaintext.tobytes())
                ser.flush()
                
                # Read back: plaintext (16) + ciphertext (16) + power samples (1600)
                expected_bytes = 32 + 1600  # 1632 bytes total
                data = bytearray()
                
                start_time = time.time()
                while len(data) < expected_bytes:
                    chunk = ser.read(expected_bytes - len(data))
                    if not chunk:
                        if time.time() - start_time > 5:
                            print(f"[!] Timeout on trace {trace_id}")
                            break
                    data.extend(chunk)
                
                if len(data) != expected_bytes:
                    print(f"[!] Incomplete data for trace {trace_id}: got {len(data)}/{expected_bytes} bytes")
                    continue
                
                # Parse response
                received_plaintext = data[0:16]
                ciphertext = data[16:32]
                power_data = data[32:]
                
                # Verify plaintext matches
                if received_plaintext != plaintext.tobytes():
                    print(f"[!] Plaintext mismatch on trace {trace_id}")
                    continue
                
                # Convert power samples to voltage values
                power_samples = []
                for i in range(0, len(power_data), 2):
                    sample = (power_data[i] << 8) | power_data[i + 1]
                    # Convert ADC reading to voltage (assuming 5V reference, 10-bit ADC)
                    voltage = sample * (5.0 / 1023.0)
                    power_samples.append(round(voltage, 4))
                
                # Write CSV row
                row = [
                    trace_id,
                    plaintext_hex,
                    bytes_to_hex(ciphertext),
                    *[f"0x{x:02X}" for x in plaintext],
                    *[f"0x{x:02X}" for x in ciphertext],
                    *power_samples
                ]
                writer.writerow(row)
                
                if trace_id % 10 == 0:
                    print(f"    Collected {trace_id}/{num_traces} traces...")
                
            except Exception as e:
                print(f"[!] Error on trace {trace_id}: {e}")
                continue
    
    ser.close()
    print(f"[+] Successfully collected traces to {output_file}")
    return True

def main():
    parser = argparse.ArgumentParser(description="Collect power traces from Arduino")
    parser.add_argument("--port", required=True, help="Serial port (e.g., COM3, /dev/ttyUSB0)")
    parser.add_argument("--traces", type=int, default=100, help="Number of traces to collect")
    parser.add_argument("--output", default="arduino_traces.csv", help="Output CSV file")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("  Arduino Power Trace Collector")
    print(f"  Port     : {args.port}")
    print(f"  Traces   : {args.traces}")
    print(f"  Output   : {args.output}")
    print("=" * 60)
    
    success = collect_arduino_traces(args.port, args.traces, args.output)
    
    if success:
        print("\n[*] Collection complete!")
        print(f"[*] Run CPA attack with:")
        print(f"    python CPA.py --csv {args.output}")
        print(f"    python CPA.py --csv {args.output} --known-key \"2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C\"")
    else:
        print("\n[!] Collection failed!")

if __name__ == "__main__":
    main()
