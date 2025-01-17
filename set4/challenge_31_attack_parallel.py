import time
import requests
from queue import PriorityQueue
from concurrent.futures import ThreadPoolExecutor

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

# Function to test a candidate signature in parallel
def test_signature_(prefix, byte_value):
    """Test a candidate prefix with a specific byte appended."""
    candidate_prefix = prefix + f"{byte_value:02x}"
    avg_time = time_request(candidate_prefix, trials=15)
    time_per_char = avg_time / (len(candidate_prefix) // 2)  # Prefix length in bytes
    return (time_per_char, candidate_prefix)

def test_signature(prefix, byte_value):
    """
    Test a candidate prefix with a specific byte appended, dynamically adjusting
    the number of trials based on the length of the prefix.
    """
    candidate_prefix = prefix + f"{byte_value:02x}"
    prefix_len = len(candidate_prefix) // 2  # Length in bytes
    
    # Dynamically determine the number of trials based on the prefix length
    # Increase trials as the prefix grows to reduce noise
    trials = max(5, (prefix_len//4 + 1) * 5)

    # Measure the average timing for the candidate prefix
    avg_time = time_request(candidate_prefix, trials=trials)
    time_per_char = avg_time / prefix_len  # Average time per character in bytes
    return (time_per_char, candidate_prefix)

# Function to perform the timing attack with parallelism
def perform_timing_attack():
    """Reconstructs the valid HMAC-SHA1 signature using a priority queue and parallelism."""
    # Priority queue: (-time_per_char, prefix_as_string)
    pq = PriorityQueue()
    pq.put((0, ""))  # Start with an empty prefix and priority 0

    recovered_signature = None
    with ThreadPoolExecutor() as executor:
        while not pq.empty():
            # Get the prefix with the highest priority (smallest negative time-per-character)
            neg_time_per_char, prefix = pq.get()
            prefix_len = len(prefix)

            if prefix_len == 40:  # We've recovered the full signature
                recovered_signature = prefix
                break

            # Submit the next 256 byte candidates in parallel
            futures = [executor.submit(test_signature, prefix, byte) for byte in range(256)]
            
            # Wait for all results and process them
            for future in futures:
                time_per_char, candidate_prefix = future.result()
                pq.put((-time_per_char, candidate_prefix))

            if prefix_len:
                print(f"Explored prefix: {prefix} (length: {prefix_len // 2}, priority: {-neg_time_per_char:.6f})")

    return recovered_signature

if __name__ == "__main__":
    print("Starting timing attack with Parallelism and PriorityQueue...")
    recovered_signature = perform_timing_attack()
    print(f"Recovered HMAC-SHA1 Signature: {recovered_signature}")