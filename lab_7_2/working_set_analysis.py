"""
Lab 7.2 - Working Set Analysis

Cyber Threat Intelligence working-set experiment.

Assignment requirements:
1. Insert 100,000 documents, each approximately 2 KB.
2. Inspect WiredTiger cache statistics using serverStatus().
3. Run random reads across the collection.
4. Observe cache-related metrics before and after the workload.

This script:
- Generates report-like CTI records.
- Targets approximately 2 KiB BSON per document.
- Inserts in batches to avoid excessive Python memory use.
- Uses integer _id values for efficient random lookup.
- Measures actual average BSON/object size using collStats.
- Records WiredTiger cache statistics.
- Performs repeated random-read passes.
- Calculates a clearly-labelled derived cache-read estimate.
- Saves final results to JSON.
"""

from __future__ import annotations

import json
import os
import random
import time
from pathlib import Path

from bson import BSON
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


# ============================================================
# Configuration
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

load_dotenv(PROJECT_ROOT / ".env")

MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb://localhost:27017"
)

MONGO_DB = os.getenv(
    "MONGO_DB",
    "sentinel_cti"
)

COLLECTION_NAME = "working_set_reports"

RESULT_FILE = (
    PROJECT_ROOT
    / "data"
    / "lab_7_2_results.json"
)

DOCUMENT_COUNT = 100_000

# 2 KiB = 2048 bytes.
TARGET_BSON_SIZE = 2 * 1024

# Insert in batches so we don't keep all 100K Python
# dictionaries in memory at once.
INSERT_BATCH_SIZE = 1_000

# Number of random reads in each pass.
READS_PER_PASS = 10_000

# Number of random-read passes.
NUMBER_OF_PASSES = 5

console = Console()


# ============================================================
# Utility functions
# ============================================================

def format_bytes(value: int | float) -> str:
    """Convert bytes to a readable unit."""

    value = float(value)

    if value < 1024:
        return f"{value:.0f} B"

    if value < 1024 * 1024:
        return f"{value / 1024:.2f} KB"

    if value < 1024 * 1024 * 1024:
        return f"{value / (1024 * 1024):.2f} MB"

    return f"{value / (1024 * 1024 * 1024):.2f} GB"


def get_cache_stats(db) -> dict:
    """
    Read the relevant WiredTiger cache statistics from
    serverStatus().
    """

    status = db.command("serverStatus")

    wired_tiger = status.get("wiredTiger", {})
    cache = wired_tiger.get("cache", {})

    return {
        "maximum_bytes_configured": int(
            cache.get(
                "maximum bytes configured",
                0
            )
        ),
        "bytes_currently_in_cache": int(
            cache.get(
                "bytes currently in the cache",
                0
            )
        ),
        "tracked_dirty_bytes": int(
            cache.get(
                "tracked dirty bytes in the cache",
                0
            )
        ),
        "pages_read_into_cache": int(
            cache.get(
                "pages read into cache",
                0
            )
        ),
        "pages_written_from_cache": int(
            cache.get(
                "pages written from cache",
                0
            )
        ),
        "pages_requested_from_cache": int(
            cache.get(
                "pages requested from the cache",
                0
            )
        ),
        "pages_evicted": int(
            cache.get(
                "eviction pages evicted by application threads",
                0
            )
        ),
    }


def calculate_cache_fill(stats: dict) -> float:
    """
    Calculate the WiredTiger cache fill percentage.

    MongoDB defines cache fill as the bytes currently in
    cache divided by the maximum configured cache.
    """

    maximum = stats["maximum_bytes_configured"]

    if maximum <= 0:
        return 0.0

    return (
        stats["bytes_currently_in_cache"]
        / maximum
    ) * 100


def calculate_derived_read_estimate(
    before: dict,
    after: dict
) -> float | None:
    """
    Derive an approximate cache-read residency percentage
    from changes in:

        pages requested from cache
        pages read into cache

    This is NOT presented as an official MongoDB "cache hit
    ratio". It is a derived estimate for this experiment.

    Why:
    - pages requested represents requests to the cache.
    - pages read into cache indicates pages brought into cache.
    - comparing their changes provides an approximate view
      of how many requests did not require a new page read.

    The value is clipped to 0-100%.
    """

    requested_delta = (
        after["pages_requested_from_cache"]
        - before["pages_requested_from_cache"]
    )

    read_delta = (
        after["pages_read_into_cache"]
        - before["pages_read_into_cache"]
    )

    if requested_delta <= 0:
        return None

    estimated_hit_ratio = (
        1 - (read_delta / requested_delta)
    ) * 100

    return max(
        0.0,
        min(100.0, estimated_hit_ratio)
    )


def build_working_set_document(index: int) -> dict:
    """
    Build a CTI/report-like document.

    The payload is generated dynamically so the final BSON
    document is close to the requested 2 KiB size.
    """

    document = {
        "_id": index,
        "working_set_id": f"WS-{index:06d}",
        "report_id": f"RPT-WS-{index:06d}",
        "report_title": (
            f"Cyber Threat Intelligence Report {index:06d}"
        ),
        "source": "Annual Security Reports Dataset",
        "year": 2026,
        "category": (
            "Global Threat Intelligence"
            if index % 5 == 0
            else "Cybersecurity"
        ),
        "threat_type": (
            "Ransomware"
            if index % 4 == 0
            else "Malware"
            if index % 4 == 1
            else "Phishing"
            if index % 4 == 2
            else "Vulnerability"
        ),
        "summary": (
            "Synthetic security-report record used for "
            "MongoDB working-set and WiredTiger cache "
            "analysis."
        ),
        "tags": [
            "cybersecurity",
            "threat-intelligence",
            "working-set"
        ],
        "payload": ""
    }

    # Calculate the BSON size without payload.
    base_size = len(BSON.encode(document))

    # BSON string values contain additional metadata, so
    # start with the required difference and then adjust.
    payload_length = max(
        0,
        TARGET_BSON_SIZE - base_size + 5
    )

    document["payload"] = "x" * payload_length

    # Adjust once more so the resulting document is as close
    # as possible to exactly 2048 bytes.
    actual_size = len(BSON.encode(document))

    if actual_size < TARGET_BSON_SIZE:
        document["payload"] += (
            "x" * (TARGET_BSON_SIZE - actual_size)
        )

    elif actual_size > TARGET_BSON_SIZE:
        remove_count = (
            actual_size - TARGET_BSON_SIZE
        )

        if remove_count < len(document["payload"]):
            document["payload"] = document["payload"][
                :-remove_count
            ]

    return document


# ============================================================
# Collection setup
# ============================================================

def reset_collection(db):
    """Drop the previous experiment collection."""

    if COLLECTION_NAME in db.list_collection_names():
        console.print(
            f"[yellow]Dropping previous collection: "
            f"{COLLECTION_NAME}[/yellow]"
        )

        db.drop_collection(COLLECTION_NAME)

    return db[COLLECTION_NAME]


# ============================================================
# Insert 100K documents
# ============================================================

def insert_working_set(collection):
    """
    Insert exactly 100,000 report-like documents in batches.
    """

    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]Creating Working Set[/bold cyan]",
            border_style="cyan"
        )
    )

    start_time = time.perf_counter()

    total_inserted = 0

    for batch_start in range(
        0,
        DOCUMENT_COUNT,
        INSERT_BATCH_SIZE
    ):
        batch_end = min(
            batch_start + INSERT_BATCH_SIZE,
            DOCUMENT_COUNT
        )

        batch = [
            build_working_set_document(index)
            for index in range(
                batch_start,
                batch_end
            )
        ]

        collection.insert_many(
            batch,
            ordered=False
        )

        total_inserted += len(batch)

        if (
            total_inserted % 10_000 == 0
            or total_inserted == DOCUMENT_COUNT
        ):
            console.print(
                f"  Inserted: "
                f"{total_inserted:>7,}/{DOCUMENT_COUNT:,}"
            )

    elapsed = time.perf_counter() - start_time

    rate = (
        total_inserted / elapsed
        if elapsed > 0
        else 0
    )

    console.print()
    console.print(
        f"[green][OK] Inserted "
        f"{total_inserted:,} documents[/green]"
    )

    console.print(
        f"     Time : {elapsed:.2f} seconds"
    )

    console.print(
        f"     Rate : {rate:,.0f} documents/sec"
    )

    return {
        "documents_inserted": total_inserted,
        "insert_time_seconds": round(
            elapsed,
            3
        ),
        "insert_rate_docs_per_second": round(
            rate,
            2
        )
    }


# ============================================================
# Measure document size / collection statistics
# ============================================================

def measure_collection_size(collection):
    """
    Use collStats to obtain MongoDB's actual average object
    size and logical collection size.
    """

    stats = collection.database.command(
        "collStats",
        COLLECTION_NAME
    )

    count = collection.count_documents({})

    avg_object_size = float(
        stats.get("avgObjSize", 0)
    )

    logical_size = int(
        stats.get("size", 0)
    )

    storage_size = int(
        stats.get("storageSize", 0)
    )

    estimated_dataset_from_average = (
        avg_object_size * count
    )

    console.print()
    console.print(
        Panel.fit(
            "[bold]Working Set Size Measurement[/bold]",
            border_style="cyan"
        )
    )

    table = Table(
        title="Collection Size",
        show_lines=True
    )

    table.add_column(
        "Metric",
        style="cyan"
    )

    table.add_column(
        "Value",
        justify="right"
    )

    table.add_row(
        "Documents",
        f"{count:,}"
    )

    table.add_row(
        "Average BSON/Object Size",
        format_bytes(avg_object_size)
    )

    table.add_row(
        "Logical Data Size",
        format_bytes(logical_size)
    )

    table.add_row(
        "Storage Size",
        format_bytes(storage_size)
    )

    table.add_row(
        "Avg Size × Document Count",
        format_bytes(
            estimated_dataset_from_average
        )
    )

    console.print(table)

    return {
        "document_count": count,
        "average_object_size_bytes": avg_object_size,
        "logical_data_size_bytes": logical_size,
        "storage_size_bytes": storage_size,
        "estimated_dataset_size_bytes": (
            estimated_dataset_from_average
        )
    }


# ============================================================
# Display WiredTiger cache information
# ============================================================

def display_cache_stats(
    title: str,
    stats: dict
):
    """Print the main WiredTiger cache statistics."""

    fill_percentage = calculate_cache_fill(
        stats
    )

    table = Table(
        title=title,
        show_lines=True
    )

    table.add_column(
        "Metric",
        style="cyan"
    )

    table.add_column(
        "Value",
        justify="right"
    )

    table.add_row(
        "Maximum Cache",
        format_bytes(
            stats["maximum_bytes_configured"]
        )
    )

    table.add_row(
        "Currently in Cache",
        format_bytes(
            stats["bytes_currently_in_cache"]
        )
    )

    table.add_row(
        "Cache Fill",
        f"{fill_percentage:.2f}%"
    )

    table.add_row(
        "Tracked Dirty Bytes",
        format_bytes(
            stats["tracked_dirty_bytes"]
        )
    )

    table.add_row(
        "Pages Requested",
        f"{stats['pages_requested_from_cache']:,}"
    )

    table.add_row(
        "Pages Read Into Cache",
        f"{stats['pages_read_into_cache']:,}"
    )

    table.add_row(
        "Pages Written From Cache",
        f"{stats['pages_written_from_cache']:,}"
    )

    table.add_row(
        "Pages Evicted",
        f"{stats['pages_evicted']:,}"
    )

    console.print(table)


# ============================================================
# Random-read workload
# ============================================================

def run_random_reads(
    collection,
    db,
    initial_cache_stats
):
    """
    Perform repeated random reads across the complete
    100,000-document ID range.
    """

    console.print()
    console.print(
        Panel.fit(
            "[bold]Random Read Workload[/bold]",
            border_style="yellow"
        )
    )

    results = []

    previous_stats = initial_cache_stats

    for pass_number in range(
        1,
        NUMBER_OF_PASSES + 1
    ):
        start = time.perf_counter()

        # Random IDs cover the entire collection range.
        random_ids = [
            random.randrange(
                0,
                DOCUMENT_COUNT
            )
            for _ in range(READS_PER_PASS)
        ]

        documents_read = 0

        for document_id in random_ids:
            document = collection.find_one(
                {"_id": document_id}
            )

            if document is not None:
                documents_read += 1

        elapsed = time.perf_counter() - start

        current_stats = get_cache_stats(db)

        estimated_hit_ratio = (
            calculate_derived_read_estimate(
                previous_stats,
                current_stats
            )
        )

        fill_percentage = calculate_cache_fill(
            current_stats
        )

        print_text = (
            f"  Pass {pass_number}/{NUMBER_OF_PASSES} | "
            f"Reads: {documents_read:,} | "
            f"Time: {elapsed:.2f}s | "
            f"Cache Fill: {fill_percentage:.2f}%"
        )

        if estimated_hit_ratio is not None:
            print_text += (
                f" | Derived read-residency estimate: "
                f"{estimated_hit_ratio:.2f}%"
            )

        console.print(print_text)

        results.append(
            {
                "pass": pass_number,
                "documents_read": documents_read,
                "elapsed_seconds": round(
                    elapsed,
                    3
                ),
                "reads_per_second": round(
                    documents_read / elapsed
                    if elapsed > 0
                    else 0,
                    2
                ),
                "cache_fill_percent": round(
                    fill_percentage,
                    3
                ),
                "derived_read_residency_estimate_percent": (
                    round(
                        estimated_hit_ratio,
                        3
                    )
                    if estimated_hit_ratio is not None
                    else None
                ),
                "cache": current_stats
            }
        )

        previous_stats = current_stats

    return results


# ============================================================
# Save results
# ============================================================

def save_results(
    insert_results: dict,
    size_results: dict,
    initial_cache: dict,
    final_cache: dict,
    read_results: list
):
    """Save experiment results for later use by the dashboard."""

    RESULT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    output = {
        "experiment": "Lab 7.2 Working Set Analysis",
        "collection": COLLECTION_NAME,
        "documents_requested": DOCUMENT_COUNT,
        "target_bson_size_bytes": TARGET_BSON_SIZE,
        "insert_results": insert_results,
        "size_results": size_results,
        "initial_cache": initial_cache,
        "final_cache": final_cache,
        "random_read_results": read_results,
        "notes": [
            (
                "Cache Fill is calculated from current cache bytes "
                "divided by maximum configured cache."
            ),
            (
                "Derived read-residency estimate is an experiment "
                "metric based on changes in pages requested versus "
                "pages read into cache. It is not presented as an "
                "official MongoDB cache-hit metric."
            )
        ]
    }

    with RESULT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            output,
            file,
            indent=2
        )

    console.print()
    console.print(
        f"[green][OK] Results saved to:[/green]\n"
        f"     {RESULT_FILE}"
    )


# ============================================================
# Main
# ============================================================

def main():
    """Run the complete Lab 7.2 experiment."""

    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]Lab 7.2 — Working Set Analysis[/bold cyan]\n"
            "Cyber Threat Intelligence Security Reports",
            border_style="cyan"
        )
    )

    client = None

    try:
        # ----------------------------------------------------
        # Connect to MongoDB
        # ----------------------------------------------------

        client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=5000
        )

        client.admin.command("ping")

        db = client[MONGO_DB]

        console.print(
            f"[OK] Connected to MongoDB at {MONGO_URI}"
        )

        console.print(
            f"[OK] Database: {MONGO_DB}"
        )

        # ----------------------------------------------------
        # Prepare collection
        # ----------------------------------------------------

        collection = reset_collection(db)

        console.print(
            f"[OK] Working-set collection: "
            f"{COLLECTION_NAME}"
        )

        # ----------------------------------------------------
        # Insert 100K documents
        # ----------------------------------------------------

        insert_results = insert_working_set(
            collection
        )

        # ----------------------------------------------------
        # Measure actual dataset size
        # ----------------------------------------------------

        size_results = measure_collection_size(
            collection
        )

        # ----------------------------------------------------
        # Initial cache snapshot
        # ----------------------------------------------------

        initial_cache = get_cache_stats(
            db
        )

        console.print()
        display_cache_stats(
            "WiredTiger Cache — Before Random Reads",
            initial_cache
        )

        # ----------------------------------------------------
        # Random reads
        # ----------------------------------------------------

        read_results = run_random_reads(
            collection,
            db,
            initial_cache
        )

        # ----------------------------------------------------
        # Final cache snapshot
        # ----------------------------------------------------

        final_cache = get_cache_stats(
            db
        )

        console.print()
        display_cache_stats(
            "WiredTiger Cache — After Random Reads",
            final_cache
        )

        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        console.print()
        console.print(
            Panel.fit(
                "[bold green]Lab 7.2 Summary[/bold green]",
                border_style="green"
            )
        )

        initial_fill = calculate_cache_fill(
            initial_cache
        )

        final_fill = calculate_cache_fill(
            final_cache
        )

        console.print(
            f"  Documents inserted : "
            f"{insert_results['documents_inserted']:,}"
        )

        console.print(
            f"  Average BSON/object size : "
            f"{format_bytes(size_results['average_object_size_bytes'])}"
        )

        console.print(
            f"  Estimated working-set size : "
            f"{format_bytes(size_results['estimated_dataset_size_bytes'])}"
        )

        console.print(
            f"  Cache fill before reads : "
            f"{initial_fill:.2f}%"
        )

        console.print(
            f"  Cache fill after reads  : "
            f"{final_fill:.2f}%"
        )

        console.print(
            "\n  Note: cache fill measures how full the "
            "WiredTiger cache is; read-residency estimates "
            "are reported separately."
        )

        # ----------------------------------------------------
        # Save results
        # ----------------------------------------------------

        save_results(
            insert_results,
            size_results,
            initial_cache,
            final_cache,
            read_results
        )

        console.print()
        console.print(
            Panel.fit(
                "[bold green]Lab 7.2 Complete[/bold green]",
                border_style="green"
            )
        )

    except PyMongoError as error:
        console.print(
            f"[bold red][ERROR] MongoDB error[/bold red]\n"
            f"{error}"
        )
        raise

    except Exception as error:
        console.print(
            f"[bold red][ERROR] Unexpected error[/bold red]\n"
            f"{error}"
        )
        raise

    finally:
        if client is not None:
            client.close()
            console.print(
                "[OK] MongoDB connection closed."
            )


if __name__ == "__main__":
    main()