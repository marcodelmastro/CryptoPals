import time
import requests
from queue import PriorityQueue

# URL of the vulnerable server
URL = "http://localhost:9000/test"

# File parameter for the request
FILE = "foo"

# Function to measure response time
def time_request(signature, trials=15):
    """Sends a request with a given signature and averages the timing over multiple trials."""
    times = []
    for _ in range(trials):
        # Pad the signature to 40 characters (20 bytes) with '00'
        padded_signature = signature.ljust(40, "0")
        start = time.time()
        response = requests.get(URL, params={"file": FILE, "signature": padded_signature})
        end = time.time()
        times.append(end - start)
    return sum(times) / len(times)  # Return the average time

# Function to perform the timing attack
def perform_timing_attack():
    """Reconstructs the valid HMAC-SHA1 signature using a thread-safe PriorityQueue."""
    # Priority queue: (-time_per_char, prefix_as_string)
    pq = PriorityQueue()
    pq.put((0, ""))  # Start with an empty prefix and priority 0

    recovered_signature = None
    while not pq.empty():
        # Get the prefix with the highest priority (smallest negative time-per-character)
        neg_time_per_char, prefix = pq.get()
        prefix_len = len(prefix)

        if prefix_len == 40:  # We've recovered the full signature (20 bytes -> 40 hex chars)
            recovered_signature = prefix
            break

        # Explore the next byte for the current prefix
        for byte in range(256):  # Test all possible values (00 to FF)
            candidate_prefix = prefix + f"{byte:02x}"
            avg_time = time_request(candidate_prefix, trials=15)
            time_per_char = avg_time / (len(candidate_prefix) // 2)  # Prefix length in bytes

            # Push the candidate to the priority queue
            pq.put((-time_per_char, candidate_prefix))

        if prefix_len:
            print(f"Explored prefix: {prefix} (length: {prefix_len // 2}, priority: {-neg_time_per_char:.6f} s)")

    return recovered_signature

if __name__ == "__main__":
    print("Starting timing attack with PriorityQueue...")
    recovered_signature = perform_timing_attack()
    print(f"Recovered HMAC-SHA1 Signature: {recovered_signature}")
