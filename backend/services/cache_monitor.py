"""
SENTINEL CTI
Lab 7.2 working-set and WiredTiger cache monitoring service.
"""

from database import client, working_set_collection


def get_working_set_metrics():
    """
    Collect working-set size and WiredTiger cache statistics.
    """

    # Collection statistics
    stats = working_set_collection_stats()

    # MongoDB server status
    server_status = client.admin.command("serverStatus")

    wired_tiger = server_status.get("wiredTiger", {})
    cache = wired_tiger.get("cache", {})

    maximum_cache = cache.get("maximum bytes configured", 0)
    current_cache = cache.get("bytes currently in the cache", 0)

    if maximum_cache:
        cache_fill = (
            current_cache / maximum_cache
        ) * 100
    else:
        cache_fill = 0

    pages_requested = cache.get(
        "pages requested from the cache",
        0
    )

    pages_read = cache.get(
        "pages read into cache",
        0
    )

    pages_written = cache.get(
        "pages written from cache",
        0
    )

    pages_evicted = cache.get(
        "pages evicted because they exceeded the in-memory maximum",
        0
    )

    return {
        "working_set": {
            "documents": working_set_collection.count_documents({}),
            "logical_size_bytes": stats.get("size", 0),
            "average_object_size_bytes": stats.get(
                "avgObjSize",
                0
            ),
            "storage_size_bytes": stats.get(
                "storageSize",
                0
            )
        },
        "wiredTiger_cache": {
            "maximum_cache_bytes": maximum_cache,
            "current_cache_bytes": current_cache,
            "cache_fill_percent": round(
                cache_fill,
                2
            ),
            "dirty_bytes": cache.get(
                "tracked dirty bytes in the cache",
                0
            ),
            "pages_requested": pages_requested,
            "pages_read_into_cache": pages_read,
            "pages_written": pages_written,
            "pages_evicted": pages_evicted
        }
    }


def working_set_collection_stats():
    """
    Return collection statistics for the 100,000-document
    working-set collection.
    """

    return client[
        working_set_collection.database.name
    ].command(
        "collStats",
        working_set_collection.name
    )