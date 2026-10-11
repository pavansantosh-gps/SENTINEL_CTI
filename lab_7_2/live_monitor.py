"""
Lab 7.2 - Try It Yourself

Live Security Report + MongoDB Cache Monitor

Every 10 seconds this script:

1. Checks the current Annual Security Reports README.
2. Identifies report records not currently stored in MongoDB.
3. Reads WiredTiger cache metrics using serverStatus().
4. Performs random reads across the 100,000-document
   working-set collection.
5. Calculates cache-fill percentage.
6. Calculates a clearly-labelled derived read-residency estimate.
7. Saves monitoring history as JSON Lines.

Source:
https://github.com/jacobdjwilson/awesome-annual-security-reports/

MongoDB:
sentinel_cti.security_reports
sentinel_cti.working_set_reports
"""

from __future__ import annotations

import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# ------------------------------------------------------------
# Make project root importable.
# ------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# Reuse the same README parser that successfully imported
# the current 2025-2026 report records.
from data.import_security_reports import (
    RAW_README_URL,
    parse_current_readme,
)


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

load_dotenv(PROJECT_ROOT / ".env")

MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb://localhost:27017",
)

MONGO_DB = os.getenv(
    "MONGO_DB",
    "sentinel_cti",
)

REPORT_COLLECTION = "security_reports"

WORKING_SET_COLLECTION = "working_set_reports"

MONITOR_LOG_FILE = (
    PROJECT_ROOT
    / "data"
    / "live_monitor_log.jsonl"
)

CHECK_INTERVAL_SECONDS = 10

# Random reads generated every cycle.
RANDOM_READ_COUNT = 1_000

REQUEST_TIMEOUT = 20

USER_AGENT = "Sentinel-CTI-Lab7-LiveMonitor/1.0"

console = Console()


# ------------------------------------------------------------
# Source monitor
# ------------------------------------------------------------

class SourceMonitor:
    """
    Maintains the last ETag so repeated checks can use
    conditional HTTP requests.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "text/plain",
            }
        )
        self.etag: str | None = None
        self.last_known_source_count: int | None = None

    def fetch_current_reports(self) -> tuple[list[dict], bool]:
        """
        Fetch and parse the current README.

        Returns:
            (reports, changed)

        changed=False means the server returned 304 Not Modified.
        """

        headers = {}

        if self.etag:
            headers["If-None-Match"] = self.etag

        response = self.session.get(
            RAW_README_URL,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 304:
            return [], False

        response.raise_for_status()

        new_etag = response.headers.get("ETag")

        if new_etag:
            self.etag = new_etag

        reports = parse_current_readme(
            response.text
        )

        self.last_known_source_count = len(
            reports
        )

        return reports, True


# ------------------------------------------------------------
# MongoDB cache metrics
# ------------------------------------------------------------

def get_cache_stats(db) -> dict:
    """
    Read documented WiredTiger cache counters from
    serverStatus().
    """

    status = db.command(
        "serverStatus"
    )

    wired_tiger = status.get(
        "wiredTiger",
        {}
    )

    cache = wired_tiger.get(
        "cache",
        {}
    )

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
        "pages_requested_from_cache": int(
            cache.get(
                "pages requested from the cache",
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
        "pages_evicted": int(
            cache.get(
                "eviction pages evicted by application threads",
                0
            )
        ),
    }


def cache_fill_percent(
    stats: dict
) -> float:
    """
    Calculate cache fill percentage:

        current cache bytes /
        maximum configured cache bytes
        × 100
    """

    maximum = stats[
        "maximum_bytes_configured"
    ]

    if maximum <= 0:
        return 0.0

    current = stats[
        "bytes_currently_in_cache"
    ]

    return (
        current / maximum
    ) * 100


def derived_read_residency(
    before: dict,
    after: dict
) -> float | None:
    """
    Calculate a derived read-residency estimate.

    This is NOT presented as an official MongoDB
    cache-hit-ratio metric.

    We compare changes in:
        pages requested from cache
        pages read into cache

    A low proportion of newly-read pages relative to
    requested pages suggests that more requests were
    served from pages already resident in cache.
    """

    requested_delta = (
        after[
            "pages_requested_from_cache"
        ]
        - before[
            "pages_requested_from_cache"
        ]
    )

    read_delta = (
        after[
            "pages_read_into_cache"
        ]
        - before[
            "pages_read_into_cache"
        ]
    )

    if requested_delta <= 0:
        return None

    estimate = (
        1
        - (
            read_delta
            / requested_delta
        )
    ) * 100

    return max(
        0.0,
        min(
            100.0,
            estimate
        )
    )


# ------------------------------------------------------------
# Random working-set reads
# ------------------------------------------------------------

def run_random_reads(
    collection
) -> dict:
    """
    Perform random reads across the full 100,000-document
    working-set ID range.
    """

    random_ids = random.sample(
        range(100_000),
        RANDOM_READ_COUNT
    )

    start = time.perf_counter()

    documents_read = 0

    # Use a batch lookup containing randomly-selected IDs.
    # The IDs cover the complete working-set range while
    # allowing MongoDB to satisfy the workload efficiently.
    cursor = collection.find(
        {
            "_id": {
                "$in": random_ids
            }
        },
        {
            "_id": 1,
            "report_title": 1,
            "category": 1,
        }
    )

    for _ in cursor:
        documents_read += 1

    elapsed = (
        time.perf_counter()
        - start
    )

    return {
        "requested_reads": RANDOM_READ_COUNT,
        "documents_read": documents_read,
        "elapsed_seconds": round(
            elapsed,
            4
        ),
        "reads_per_second": round(
            documents_read / elapsed
            if elapsed > 0
            else 0,
            2
        )
    }


# ------------------------------------------------------------
# Detect reports not stored in MongoDB
# ------------------------------------------------------------

def find_new_reports(
    reports_collection,
    source_reports: list[dict]
) -> list[dict]:
    """
    Compare current source report URLs with MongoDB.

    repository_report_url is the unique identity used by
    our importer.
    """

    source_urls = [
        report[
            "repository_report_url"
        ]
        for report in source_reports
        if report.get(
            "repository_report_url"
        )
    ]

    if not source_urls:
        return []

    existing_urls = set(
        reports_collection.distinct(
            "repository_report_url",
            {
                "repository_report_url": {
                    "$in": source_urls
                }
            }
        )
    )

    return [
        report
        for report in source_reports
        if report.get(
            "repository_report_url"
        )
        not in existing_urls
    ]


# ------------------------------------------------------------
# Formatting
# ------------------------------------------------------------

def format_bytes(
    value: int | float
) -> str:
    """Format byte values for the terminal."""

    value = float(value)

    if value < 1024:
        return f"{value:.0f} B"

    if value < 1024 * 1024:
        return (
            f"{value / 1024:.2f} KB"
        )

    if value < 1024 * 1024 * 1024:
        return (
            f"{value / (1024 * 1024):.2f} MB"
        )

    return (
        f"{value / (1024 * 1024 * 1024):.2f} GB"
    )


def print_cache_table(
    stats: dict,
    derived_hit: float | None
):
    """Display MongoDB cache information."""

    fill = cache_fill_percent(
        stats
    )

    table = Table(
        title="WiredTiger Cache"
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
            stats[
                "maximum_bytes_configured"
            ]
        )
    )

    table.add_row(
        "Currently in Cache",
        format_bytes(
            stats[
                "bytes_currently_in_cache"
            ]
        )
    )

    table.add_row(
        "Cache Fill",
        f"{fill:.2f}%"
    )

    table.add_row(
        "Dirty Bytes",
        format_bytes(
            stats[
                "tracked_dirty_bytes"
            ]
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
        "Pages Written",
        f"{stats['pages_written_from_cache']:,}"
    )

    table.add_row(
        "Pages Evicted",
        f"{stats['pages_evicted']:,}"
    )

    if derived_hit is not None:
        table.add_row(
            "Derived Read-Residency Estimate",
            f"{derived_hit:.2f}%"
        )

    console.print(table)


def print_new_reports(
    reports: list[dict]
):
    """Display newly detected reports."""

    if not reports:
        console.print(
            "\n[green]No new reports detected.[/green]"
        )
        return

    console.print()
    console.print(
        Panel.fit(
            f"[bold yellow]NEW REPORTS DETECTED: "
            f"{len(reports)}[/bold yellow]",
            border_style="yellow"
        )
    )

    table = Table(
        title="New Security Reports"
    )

    table.add_column(
        "Year",
        justify="right"
    )

    table.add_column(
        "Category"
    )

    table.add_column(
        "Organization"
    )

    table.add_column(
        "Title",
        style="cyan"
    )

    for report in reports:
        table.add_row(
            str(report.get("year", "")),
            str(report.get("category", "")),
            str(
                report.get(
                    "organization",
                    ""
                )
            )[:25],
            str(
                report.get(
                    "title",
                    ""
                )
            )[:55],
        )

    console.print(table)


# ------------------------------------------------------------
# Save monitor history
# ------------------------------------------------------------

def save_monitor_record(
    record: dict
):
    """
    Append one monitoring cycle as JSON Lines.

    JSON Lines is convenient for later dashboard analytics.
    """

    MONITOR_LOG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with MONITOR_LOG_FILE.open(
        "a",
        encoding="utf-8"
    ) as file:
        file.write(
            json.dumps(
                record,
                ensure_ascii=False
            )
            + "\n"
        )


# ------------------------------------------------------------
# One monitoring cycle
# ------------------------------------------------------------

def run_cycle(
    monitor: SourceMonitor,
    db
) -> bool:
    """
    Run one complete monitoring cycle.

    Returns False if the source could not be fetched.
    """

    reports_collection = db[
        REPORT_COLLECTION
    ]

    working_set_collection = db[
        WORKING_SET_COLLECTION
    ]

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    console.print()
    console.print(
        Panel.fit(
            f"[bold cyan]Monitoring Cycle[/bold cyan]\n"
            f"{timestamp}",
            border_style="cyan"
        )
    )

    # --------------------------------------------------------
    # Source check
    # --------------------------------------------------------

    try:
        source_reports, changed = (
            monitor.fetch_current_reports()
        )
    except requests.RequestException as error:
        console.print(
            "[bold red]Source check failed:[/bold red]"
        )
        console.print(error)

        return False

    if changed:
        new_reports = find_new_reports(
            reports_collection,
            source_reports
        )

        source_count = len(
            source_reports
        )

        database_count = (
            reports_collection.count_documents({})
        )

        console.print(
            f"\nSource reports     : "
            f"{source_count:,}"
        )

        console.print(
            f"Database reports   : "
            f"{database_count:,}"
        )

        print_new_reports(
            new_reports
        )

    else:
        new_reports = []

        console.print(
            "\n[green]Source unchanged "
            "(HTTP 304).[/green]"
        )

    # --------------------------------------------------------
    # Cache snapshot before random reads
    # --------------------------------------------------------

    cache_before = get_cache_stats(
        db
    )

    # --------------------------------------------------------
    # Random working-set reads
    # --------------------------------------------------------

    read_result = run_random_reads(
        working_set_collection
    )

    # --------------------------------------------------------
    # Cache snapshot after reads
    # --------------------------------------------------------

    cache_after = get_cache_stats(
        db
    )

    derived_hit = (
        derived_read_residency(
            cache_before,
            cache_after
        )
    )

    # --------------------------------------------------------
    # Display results
    # --------------------------------------------------------

    console.print()
    console.print(
        Panel.fit(
            "[bold]Working-Set Read Workload[/bold]",
            border_style="yellow"
        )
    )

    console.print(
        f"  Requested reads : "
        f"{read_result['requested_reads']:,}"
    )

    console.print(
        f"  Documents read  : "
        f"{read_result['documents_read']:,}"
    )

    console.print(
        f"  Elapsed time    : "
        f"{read_result['elapsed_seconds']:.4f} s"
    )

    console.print(
        f"  Read throughput : "
        f"{read_result['reads_per_second']:,.0f} docs/s"
    )

    print_cache_table(
        cache_after,
        derived_hit
    )

    # --------------------------------------------------------
    # Save history
    # --------------------------------------------------------

    record = {
        "timestamp_utc": timestamp,
        "source": {
            "changed": changed,
            "source_report_count": (
                len(source_reports)
                if changed
                else monitor.last_known_source_count
            ),
            "database_report_count": (
                reports_collection.count_documents({})
            ),
            "new_report_count": len(
                new_reports
            ),
            "new_reports": [
                {
                    "title": report.get(
                        "title"
                    ),
                    "organization": report.get(
                        "organization"
                    ),
                    "year": report.get(
                        "year"
                    ),
                    "category": report.get(
                        "category"
                    ),
                    "repository_report_url": report.get(
                        "repository_report_url"
                    ),
                }
                for report in new_reports
            ],
        },
        "random_reads": read_result,
        "cache_before": cache_before,
        "cache_after": cache_after,
        "cache_fill_percent": round(
            cache_fill_percent(
                cache_after
            ),
            4
        ),
        "derived_read_residency_estimate_percent": (
            round(
                derived_hit,
                4
            )
            if derived_hit is not None
            else None
        ),
    }

    save_monitor_record(
        record
    )

    console.print()
    console.print(
        "[green][OK] Monitoring record saved.[/green]"
    )

    return True


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():
    """Run the monitor until Ctrl+C."""

    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]SENTINEL CTI — LIVE REPORT "
            "AND CACHE MONITOR[/bold cyan]\n"
            "Lab 7.2 Try-It-Yourself",
            border_style="cyan"
        )
    )

    console.print()
    console.print(
        f"Check interval : "
        f"{CHECK_INTERVAL_SECONDS} seconds"
    )

    console.print(
        f"Random reads   : "
        f"{RANDOM_READ_COUNT:,} per cycle"
    )

    console.print(
        "Press Ctrl+C to stop."
    )

    client = None

    try:
        # ----------------------------------------------------
        # MongoDB
        # ----------------------------------------------------

        client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=5000
        )

        client.admin.command(
            "ping"
        )

        db = client[
            MONGO_DB
        ]

        # Make sure required collections exist.
        collection_names = (
            db.list_collection_names()
        )

        missing = [
            name
            for name in (
                REPORT_COLLECTION,
                WORKING_SET_COLLECTION
            )
            if name not in collection_names
        ]

        if missing:
            raise RuntimeError(
                "Required collection(s) missing: "
                + ", ".join(missing)
            )

        console.print(
            f"\n[green][OK] Connected to MongoDB "
            f"at {MONGO_URI}[/green]"
        )

        console.print(
            f"[green][OK] Database: "
            f"{MONGO_DB}[/green]"
        )

        console.print(
            f"[green][OK] Security reports: "
            f"{db[REPORT_COLLECTION].count_documents({}):,}[/green]"
        )

        console.print(
            f"[green][OK] Working set: "
            f"{db[WORKING_SET_COLLECTION].count_documents({}):,}[/green]"
        )

        monitor = SourceMonitor()

        # ----------------------------------------------------
        # Continuous monitoring
        # ----------------------------------------------------

        while True:
            cycle_start = time.perf_counter()

            run_cycle(
                monitor,
                db
            )

            elapsed = (
                time.perf_counter()
                - cycle_start
            )

            sleep_seconds = max(
                0,
                CHECK_INTERVAL_SECONDS
                - elapsed
            )

            console.print()
            console.print(
                f"[dim]Next check in "
                f"{sleep_seconds:.1f} seconds...[/dim]"
            )

            time.sleep(
                sleep_seconds
            )

    except KeyboardInterrupt:
        console.print()
        console.print(
            Panel.fit(
                "[bold yellow]Monitoring stopped "
                "by user.[/bold yellow]",
                border_style="yellow"
            )
        )

    except PyMongoError as error:
        console.print(
            f"[bold red]MongoDB error:[/bold red]\n"
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