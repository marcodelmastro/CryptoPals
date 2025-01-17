import time
import requests

# URL of the vulnerable server
URL = "http://localhost:9000/test"

# File parameter for the request
FILE = "foo"

# Function to measure response time
def time_request(signature, trials=15):
    """Sends a request with a given signature and averages the timing over multiple trials."""
    times = []
    for _ in range(trials):
        start = time.time()
        response = requests.get(URL, params={"file": FILE, "signature": signature})
        end = time.time()
        times.append(end - start)
    return sum(times) / len(times)  # Return the average time

# Function to perform the timing attack
def perform_timing_attack():
    """Reconstructs the valid HMAC-SHA1 signature byte by byte using a ratio-based approach."""
    signature = ["00"] * 20  # SHA1 is 20 bytes (40 hex characters)
    for i in range(20):
        best_time_per_char = 0
        best_byte = None

        for byte in range(256):  # Test all possible values (00 to FF)
            signature[i] = f"{byte:02x}"
            test_sig = "".join(signature)
            avg_time = time_request(test_sig, trials=15)

            # Calculate time per character for this prefix
            time_per_char = avg_time / (i + 1)

            if time_per_char > best_time_per_char:
                best_time_per_char = time_per_char
                best_byte = byte

        # Finalize the byte selection for this position
        signature[i] = f"{best_byte:02x}"
        print(f"Recovered byte {i + 1}: {signature[i]} (time per char: {best_time_per_char:.6f} seconds)")

    return "".join(signature)

if __name__ == "__main__":
    print("Starting timing attack using time-per-character heuristic...")
    recovered_signature = perform_timing_attack()
    print(f"Recovered HMAC-SHA1 Signature: {recovered_signature}")
