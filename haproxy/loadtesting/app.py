import asyncio
import time
import aiohttp

# --- CONFIGURATION ---
TARGET_URL = "https://localhost:443"  # Replace with your web server URL
TOTAL_REQUESTS = 100000               # Total number of connections to open
CONCURRENT_LIMIT = 500                # Maximum simultaneous open connections
TIMEOUT_SECONDS = 10                 # Timeout for individual requests

async def send_request(session: aiohttp.ClientSession, request_id: int, results: dict):
    """Opens a single connection and sends a GET request."""
    try:
        start_time = time.time()
        async with session.get(TARGET_URL, timeout=TIMEOUT_SECONDS) as response:
            await response.read()  # Read body to fully close out the data stream
            duration = time.time() - start_time
            
            status = response.status
            results["statuses"][status] = results["statuses"].get(status, 0) + 1
            results["latencies"].append(duration)
    except asyncio.TimeoutError:
        results["errors"] += 1
        results["statuses"]["Timeout"] = results["statuses"].get("Timeout", 0) + 1
    except Exception as e:
        results["errors"] += 1
        results["statuses"][type(e).__name__] = results["statuses"].get(type(e).__name__, 0) + 1

async def main():
    # Initialize metric counters
    results = {"statuses": {}, "latencies": [], "errors": 0}
    
    # Enforce concurrency limits using a Semaphore
    semaphore = asyncio.Semaphore(CONCURRENT_LIMIT)
    
    # Configure connection pooling limits
    connector = aiohttp.TCPConnector(limit=CONCURRENT_LIMIT, ttl_dns_cache=300, ssl=False)
    
    print(f"Starting load test against: {TARGET_URL}")
    print(f"Total Requests: {TOTAL_REQUESTS} | Max Concurrency: {CONCURRENT_LIMIT}\n")
    
    test_start = time.time()
    
    async with aiohttp.ClientSession(connector=connector) as session:
        async def worker(req_id):
            async with semaphore:
                await send_request(session, req_id, results)
        
        # Schedule all requests concurrently
        tasks = [worker(i) for i in range(TOTAL_REQUESTS)]
        await asyncio.gather(*tasks)
        
    total_duration = time.time() - test_start
    
    # --- REPORTING ---
    print("=" * 40)
    print(" LOAD TEST RESULTS")
    print("=" * 40)
    print(f"Total Time Taken:  {total_duration:.2f} seconds")
    print(f"Requests per Sec:  {TOTAL_REQUESTS / total_duration:.2f}")
    print(f"Total Errors:      {results['errors']}")
    print("\nResponse Status Codes:")
    for status, count in results["statuses"].items():
        print(f"  [{status}]: {count} requests")
        
    if results["latencies"]:
        avg_latency = sum(results["latencies"]) / len(results["latencies"])
        print(f"\nAverage Latency:   {avg_latency * 1000:.2f} ms")

if __name__ == "__main__":
    # Install required dependency: pip install aiohttp
    asyncio.run(main())
