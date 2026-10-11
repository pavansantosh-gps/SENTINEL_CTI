"""
Lab 7.1 - Analyze a Production Schema

Cyber Threat Intelligence production-schema analysis.

This experiment:
1. Loads CTI seed data from JSON.
2. Creates MongoDB collections for sources, reports, threats, and IOCs.
3. Demonstrates embedding vs referencing decisions.
4. Calculates BSON document sizes using MongoDB's $bsonSize expression.
5. Calculates average/minimum/maximum report size.
6. Verifies document sizes against MongoDB's 16 MiB document limit.
7. Simulates document growth with increasing numbers of embedded IOCs.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pymongo import MongoClient
from pymongo.errors import PyMongoError
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from dotenv import load_dotenv
import os


# ------------------------------------------------------------
# Paths and configuration
# ------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_FILE = PROJECT_ROOT / "data" / "cti_7_1_seed.json"

ENV_FILE = PROJECT_ROOT / ".env"
load_dotenv(ENV_FILE)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "sentinel_cti")

console = Console()

# MongoDB's maximum BSON document size is 16 MiB.
MAX_DOCUMENT_SIZE = 16 * 1024 * 1024


# ------------------------------------------------------------
# Utility functions
# ------------------------------------------------------------

def load_seed_data() -> dict:
    """Load and validate the CTI seed JSON file."""

    if not DATA_FILE.exists():
        raise FileNotFoundError(
            f"Seed file not found:\n{DATA_FILE}"
        )

    with DATA_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    required_sections = {"sources", "threats", "iocs", "reports"}

    missing = required_sections - set(data.keys())

    if missing:
        raise ValueError(
            f"Seed file is missing sections: {sorted(missing)}"
        )

    return data


def connect_to_mongodb():
    """Connect to MongoDB and return client + database."""

    client = MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=5000
    )

    # Force connection check immediately.
    client.admin.command("ping")

    db = client[MONGO_DB]

    return client, db


def reset_collection(db, collection_name: str):
    """Drop a collection if it exists and return a fresh collection."""

    if collection_name in db.list_collection_names():
        db.drop_collection(collection_name)

    return db[collection_name]


def bson_size_for_document(collection, document_id) -> int:
    """
    Calculate the BSON size of one document using $bsonSize.

    $bsonSize is an aggregation expression, so it is evaluated
    inside an aggregation pipeline.
    """

    result = list(
        collection.aggregate(
            [
                {
                    "$match": {
                        "_id": document_id
                    }
                },
                {
                    "$project": {
                        "_id": 0,
                        "bson_size": {
                            "$bsonSize": "$$ROOT"
                        }
                    }
                }
            ]
        )
    )

    if not result:
        raise ValueError(
            f"Document {document_id} was not found."
        )

    return int(result[0]["bson_size"])


def format_bytes(value: int) -> str:
    """Format bytes into a readable value."""

    if value < 1024:
        return f"{value} B"

    if value < 1024 * 1024:
        return f"{value / 1024:.2f} KB"

    return f"{value / (1024 * 1024):.2f} MB"


# ------------------------------------------------------------
# Data loading
# ------------------------------------------------------------

def insert_cti_data(db, data: dict):
    """Insert the CTI seed data into four collections."""

    sources = reset_collection(db, "sources")
    threats = reset_collection(db, "threats")
    iocs = reset_collection(db, "iocs")
    reports = reset_collection(db, "reports")

    sources.insert_many(data["sources"])
    threats.insert_many(data["threats"])
    iocs.insert_many(data["iocs"])
    reports.insert_many(data["reports"])

    return sources, threats, iocs, reports


# ------------------------------------------------------------
# Schema analysis
# ------------------------------------------------------------

def print_schema_analysis():
    """Display the intended embedding/reference decisions."""

    console.print()
    console.print(
        Panel.fit(
            "[bold]CTI Production Schema — Embed vs Reference[/bold]",
            border_style="cyan"
        )
    )

    table = Table(
        title="Relationship Design",
        show_lines=True
    )

    table.add_column("Relationship", style="cyan")
    table.add_column("Design", style="green")
    table.add_column("Reason")

    table.add_row(
        "Report → Source",
        "REFERENCE",
        (
            "A source can publish many reports. "
            "Referencing avoids repeating source metadata."
        )
    )

    table.add_row(
        "Report → Threat",
        "REFERENCE",
        (
            "A threat can appear in multiple reports and "
            "has an independent lifecycle."
        )
    )

    table.add_row(
        "Report → IOC",
        "REFERENCE",
        (
            "An IOC can occur in multiple reports and can "
            "be independently searched, updated, and reused."
        )
    )

    table.add_row(
        "Report → Tags",
        "EMBED",
        (
            "Tags are small, bounded values that are normally "
            "read together with the report."
        )
    )

    table.add_row(
        "Report → Classification",
        "EMBED",
        (
            "Classification is a small bounded object that "
            "belongs directly to the report."
        )
    )

    table.add_row(
        "Report → Observations",
        "EMBED",
        (
            "The current observation list is intentionally "
            "small and bounded for this schema."
        )
    )

    console.print(table)


# ------------------------------------------------------------
# BSON size analysis
# ------------------------------------------------------------

def analyze_report_sizes(reports_collection):
    """Calculate BSON sizes for all CTI report documents."""

    console.print()
    console.print(
        Panel.fit(
            "[bold]Document Size Analysis ($bsonSize)[/bold]",
            border_style="cyan"
        )
    )

    table = Table(
        title="CTI Report Document Sizes",
        show_lines=True
    )

    table.add_column("Report", style="cyan", width=36)
    table.add_column("Threat Refs", justify="right")
    table.add_column("IOC Refs", justify="right")
    table.add_column("BSON Size", justify="right")
    table.add_column("% of 16 MiB", justify="right")

    sizes = []

    for report in reports_collection.find().sort("report_id", 1):
        size = bson_size_for_document(
            reports_collection,
            report["_id"]
        )

        sizes.append(size)

        percentage = (size / MAX_DOCUMENT_SIZE) * 100

        table.add_row(
            report["title"][:36],
            str(len(report.get("threat_ids", []))),
            str(len(report.get("ioc_ids", []))),
            format_bytes(size),
            f"{percentage:.5f}%"
        )

    console.print(table)

    average_size = sum(sizes) / len(sizes)
    minimum_size = min(sizes)
    maximum_size = max(sizes)

    console.print()
    console.print(
        f"  Average BSON size : {format_bytes(int(average_size))}"
    )
    console.print(
        f"  Minimum BSON size : {format_bytes(minimum_size)}"
    )
    console.print(
        f"  Maximum BSON size : {format_bytes(maximum_size)}"
    )

    maximum_percentage = (
        maximum_size / MAX_DOCUMENT_SIZE
    ) * 100

    console.print(
        f"  16 MiB limit      : {MAX_DOCUMENT_SIZE:,} bytes"
    )

    console.print(
        f"  Largest document  : "
        f"{maximum_percentage:.5f}% of the 16 MiB limit"
    )

    if maximum_size < MAX_DOCUMENT_SIZE:
        console.print(
            "  Status            : [green]SAFE — no report "
            "document approaches the 16 MiB limit.[/green]"
        )
    else:
        console.print(
            "  Status            : [red]WARNING — a document "
            "reached/exceeded the 16 MiB limit.[/red]"
        )


# ------------------------------------------------------------
# Large-document growth experiment
# ------------------------------------------------------------

def simulate_large_embedded_document(db):
    """
    Simulate the growth of a report containing an embedded IOC array.

    This does not insert these oversized test documents permanently.
    The documents are measured using a temporary collection.
    """

    console.print()
    console.print(
        Panel.fit(
            "[bold]Large Embedded Document Growth Simulation[/bold]",
            border_style="yellow"
        )
    )

    test_collection_name = "bson_growth_test"

    if test_collection_name in db.list_collection_names():
        db.drop_collection(test_collection_name)

    test_collection = db[test_collection_name]

    table = Table(
        title="Embedded IOC Growth",
        show_lines=True
    )

    table.add_column("Embedded IOCs", justify="right")
    table.add_column("BSON Size", justify="right")
    table.add_column("% of 16 MiB", justify="right")
    table.add_column("Status")

    for count in (100, 1000, 10000):
        document = {
            "report_id": f"GROWTH-{count}",
            "title": "Large Embedded CTI Report",
            "category": "Security Analysis",
            "iocs": [
                {
                    "indicator": f"demo-indicator-{i}",
                    "type": "Domain",
                    "confidence": 80,
                    "category": "Demo Threat",
                    "first_seen": "2026-01-01"
                }
                for i in range(count)
            ]
        }

        inserted = test_collection.insert_one(document)

        size = bson_size_for_document(
            test_collection,
            inserted.inserted_id
        )

        percentage = (
            size / MAX_DOCUMENT_SIZE
        ) * 100

        if size < MAX_DOCUMENT_SIZE:
            status = "[green]SAFE[/green]"
        else:
            status = "[red]EXCEEDS LIMIT[/red]"

        table.add_row(
            f"{count:,}",
            format_bytes(size),
            f"{percentage:.5f}%",
            status
        )

        test_collection.delete_one(
            {"_id": inserted.inserted_id}
        )

    console.print(table)

    db.drop_collection(test_collection_name)


# ------------------------------------------------------------
# Main program
# ------------------------------------------------------------

def main():
    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]Lab 7.1 — Analyze a Production Schema[/bold cyan]\n"
            "Cyber Threat Intelligence Platform",
            border_style="cyan"
        )
    )

    client = None

    try:
        # Load seed data.
        data = load_seed_data()

        console.print(
            f"[OK] Loaded CTI seed data from: {DATA_FILE}"
        )

        console.print(
            f"     Sources : {len(data['sources'])}"
        )
        console.print(
            f"     Threats : {len(data['threats'])}"
        )
        console.print(
            f"     IOCs    : {len(data['iocs'])}"
        )
        console.print(
            f"     Reports : {len(data['reports'])}"
        )

        # Connect to MongoDB.
        client, db = connect_to_mongodb()

        console.print(
            f"[OK] Connected to MongoDB at {MONGO_URI}"
        )
        console.print(
            f"[OK] Database: {MONGO_DB}"
        )

        # Insert data.
        sources, threats, iocs, reports = insert_cti_data(
            db,
            data
        )

        console.print()
        console.print(
            "[OK] CTI collections created and populated."
        )

        console.print(
            f"     sources : {sources.count_documents({}):,}"
        )
        console.print(
            f"     threats : {threats.count_documents({}):,}"
        )
        console.print(
            f"     iocs    : {iocs.count_documents({}):,}"
        )
        console.print(
            f"     reports : {reports.count_documents({}):,}"
        )

        # Schema analysis.
        print_schema_analysis()

        # BSON size analysis.
        analyze_report_sizes(reports)

        # Large document experiment.
        simulate_large_embedded_document(db)

        console.print()
        console.print(
            Panel.fit(
                "[bold green]Lab 7.1 Complete[/bold green]",
                border_style="green"
            )
        )

    except FileNotFoundError as error:
        console.print(
            f"[red][ERROR] {error}[/red]"
        )
        sys.exit(1)

    except json.JSONDecodeError as error:
        console.print(
            f"[red][ERROR] Invalid JSON file: {error}[/red]"
        )
        sys.exit(1)

    except PyMongoError as error:
        console.print(
            f"[red][ERROR] MongoDB error:[/red]\n{error}"
        )
        sys.exit(1)

    except Exception as error:
        console.print(
            f"[red][ERROR] Unexpected error:[/red]\n{error}"
        )
        sys.exit(1)

    finally:
        if client is not None:
            client.close()
            console.print("[OK] MongoDB connection closed.")


if __name__ == "__main__":
    main()