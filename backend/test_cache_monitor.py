from services.cache_monitor import get_working_set_metrics


print("=" * 60)
print("SENTINEL CTI — CACHE MONITOR TEST")
print("=" * 60)

try:
    result = get_working_set_metrics()

    working_set = result["working_set"]
    cache = result["wiredTiger_cache"]

    print("\nWorking Set")
    print("-" * 40)
    print(f"Documents              : {working_set['documents']}")
    print(f"Logical size           : {working_set['logical_size_bytes']} bytes")
    print(f"Average object size    : {working_set['average_object_size_bytes']} bytes")
    print(f"Storage size           : {working_set['storage_size_bytes']} bytes")

    print("\nWiredTiger Cache")
    print("-" * 40)
    print(f"Maximum cache          : {cache['maximum_cache_bytes']} bytes")
    print(f"Current cache          : {cache['current_cache_bytes']} bytes")
    print(f"Cache fill             : {cache['cache_fill_percent']}%")
    print(f"Dirty bytes            : {cache['dirty_bytes']}")
    print(f"Pages requested        : {cache['pages_requested']}")
    print(f"Pages read into cache  : {cache['pages_read_into_cache']}")
    print(f"Pages written          : {cache['pages_written']}")
    print(f"Pages evicted          : {cache['pages_evicted']}")

    print("\n[OK] Cache monitoring service is working.")

except Exception as error:
    print("\n[ERROR] Cache monitoring failed.")
    print(f"Reason: {error}")