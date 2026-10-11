"""
Lab 7.1 - Try It Yourself
Embedded Redesign of a Referenced Threat Relationship

This experiment compares:

1. Report -> Threat using references
2. Report -> Threat using an embedded threat document

Selected actual threat:
    THR-001 / DemoRansom / Ransomware

The experiment measures:
- Query performance
- BSON size difference
- Update complexity
"""

from __future__ import annotations

import json
import os
import time
from copy import deepcopy
from pathlib import Path

from dotenv import load_dotenv
from pymongo import MongoClient
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


# ------------------------------------------------------------
# Project configuration
# ------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_FILE = PROJECT_ROOT / "data" / "cti_7_1_seed.json"

load_dotenv(PROJECT_ROOT / ".env")

MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb://localhost:27017"
)

MONGO_DB = os.getenv(
    "MONGO_DB",
    "sentinel_cti"
)

console = Console()

# The assignment asks us to decide which source/entity is
# an actual threat. We deliberately select the threat entity,
# not the report publisher.
SELECTED_THREAT_ID = "THR-001"

# Number of measured executions for query timing.
BENCHMARK_RUNS = 500


# ------------------------------------------------------------
# Utility functions
# ------------------------------------------------------------

def load_seed_data() -> dict:
    """Load the previously validated CTI seed dataset."""

    if not DATA_FILE.exists():
        raise FileNotFoundError(
            f"Seed file not found:\n{DATA_FILE}"
        )

    with DATA_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def reset_collection(db, name: str):
    """Drop an existing test collection and return a fresh one."""

    if name in db.list_collection_names():
        db.drop_collection(name)

    return db[name]


def get_bson_size(collection, report_id: str) -> int:
    """
    Calculate the BSON size of one report using $bsonSize.

    $bsonSize is evaluated inside an aggregation pipeline.
    """

    result = list(
        collection.aggregate(
            [
                {
                    "$match": {
                        "report_id": report_id
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
            f"Report {report_id} was not found."
        )

    return int(result[0]["bson_size"])


def format_bytes(value: int) -> str:
    """Return a human-readable byte value."""

    if value < 1024:
        return f"{value} B"

    if value < 1024 * 1024:
        return f"{value / 1024:.2f} KB"

    return f"{value / (1024 * 1024):.2f} MB"


# ------------------------------------------------------------
# Prepare two schema designs
# ------------------------------------------------------------

def prepare_designs(db, data: dict):
    """
    Create isolated collections for the reference and embedded
    designs so the experiment does not modify the main Lab 7.1
    collections.
    """

    reference_reports = reset_collection(
        db,
        "reports_reference_design"
    )

    embedded_reports = reset_collection(
        db,
        "reports_embedded_design"
    )

    redesign_threats = reset_collection(
        db,
        "threats_redesign_test"
    )

    # --------------------------------------------------------
    # Reference design
    # --------------------------------------------------------

    reference_reports.insert_many(
        deepcopy(data["reports"])
    )

    redesign_threats.insert_many(
        deepcopy(data["threats"])
    )

    # --------------------------------------------------------
    # Embedded design
    # --------------------------------------------------------

    threat_map = {
        threat["threat_id"]: threat
        for threat in data["threats"]
    }

    embedded_documents = []

    for report in data["reports"]:
        document = deepcopy(report)

        # We are redesigning specifically the relationship
        # Report -> THR-001 as an embedded relationship.
        selected_threat = threat_map.get(
            SELECTED_THREAT_ID
        )

        if (
            selected_threat is not None
            and SELECTED_THREAT_ID in report.get(
                "threat_ids",
                []
            )
        ):
            document["embedded_threat"] = deepcopy(
                selected_threat
            )
        else:
            document["embedded_threat"] = None

        embedded_documents.append(document)

    embedded_reports.insert_many(
        embedded_documents
    )

    # Helpful indexes for the comparison.
    reference_reports.create_index(
        [("report_id", 1)],
        name="idx_report_id_reference"
    )

    reference_reports.create_index(
        [("threat_ids", 1)],
        name="idx_threat_ids_reference"
    )

    embedded_reports.create_index(
        [("report_id", 1)],
        name="idx_report_id_embedded"
    )

    embedded_reports.create_index(
        [("embedded_threat.threat_id", 1)],
        name="idx_embedded_threat_id"
    )

    redesign_threats.create_index(
        [("threat_id", 1)],
        unique=True,
        name="idx_threat_id"
    )

    return (
        reference_reports,
        embedded_reports,
        redesign_threats
    )


# ------------------------------------------------------------
# Display schema decision
# ------------------------------------------------------------

def print_schema_decision(threat_document: dict):
    """Display the selected relationship and design."""

    console.print(
        Panel.fit(
            "[bold cyan]7.1 Try-It-Yourself: Embedded Redesign[/bold cyan]",
            border_style="cyan"
        )
    )

    console.print()
    console.print(
        "[bold]Selected actual threat:[/bold]"
    )

    console.print(
        f"  Threat ID : {threat_document['threat_id']}"
    )

    console.print(
        f"  Name      : {threat_document['name']}"
    )

    console.print(
        f"  Type      : {threat_document['type']}"
    )

    console.print(
        f"  Severity  : {threat_document['severity']}"
    )

    console.print()

    table = Table(
        title="Reference vs Embedded Design",
        show_lines=True
    )

    table.add_column("Aspect", style="cyan")
    table.add_column("Reference Design")
    table.add_column("Embedded Design")

    table.add_row(
        "Relationship",
        "Report → threat_id",
        "Report → embedded_threat"
    )

    table.add_row(
        "Threat storage",
        "Separate collection",
        "Inside report"
    )

    table.add_row(
        "Data duplication",
        "Low",
        "Possible across reports"
    )

    table.add_row(
        "Independent threat updates",
        "Simple",
        "Requires multiple report updates"
    )

    table.add_row(
        "Report + threat retrieval",
        "Requires lookup/reference resolution",
        "Available in one document"
    )

    console.print(table)


# ------------------------------------------------------------
# Query functions
# ------------------------------------------------------------

def reference_query(
    reports_collection,
    threats_collection
):
    """
    Resolve a report and its threat through a MongoDB $lookup.
    """

    pipeline = [
        {
            "$match": {
                "report_id": "RPT-001"
            }
        },
        {
            "$lookup": {
                "from": threats_collection.name,
                "localField": "threat_ids",
                "foreignField": "threat_id",
                "as": "threat_details"
            }
        },
        {
            "$project": {
                "_id": 0,
                "report_id": 1,
                "title": 1,
                "threat_details": 1
            }
        }
    ]

    return list(
        reports_collection.aggregate(pipeline)
    )


def embedded_query(reports_collection):
    """
    Resolve a report and its embedded threat in one document read.
    """

    return list(
        reports_collection.find(
            {
                "report_id": "RPT-001"
            },
            {
                "_id": 0,
                "report_id": 1,
                "title": 1,
                "embedded_threat": 1
            }
        )
    )


# ------------------------------------------------------------
# Query performance benchmark
# ------------------------------------------------------------

def benchmark_query(function, runs: int = BENCHMARK_RUNS):
    """
    Measure average query execution time.

    The result is environment-dependent because this is a
    small synthetic dataset running on the local MongoDB
    instance.
    """

    # Warm up the query.
    for _ in range(20):
        function()

    start = time.perf_counter()

    for _ in range(runs):
        function()

    elapsed = time.perf_counter() - start

    average_ms = (
        elapsed / runs
    ) * 1000

    return average_ms


def run_query_comparison(
    reference_reports,
    embedded_reports,
    redesign_threats
):
    """Compare reference and embedded query performance."""

    reference_average = benchmark_query(
        lambda: reference_query(
            reference_reports,
            redesign_threats
        )
    )

    embedded_average = benchmark_query(
        lambda: embedded_query(
            embedded_reports
        )
    )

    console.print()
    console.print(
        Panel.fit(
            "[bold]Query Performance Comparison[/bold]",
            border_style="yellow"
        )
    )

    table = Table(
        title=f"Average Query Time ({BENCHMARK_RUNS:,} runs)",
        show_lines=True
    )

    table.add_column("Design", style="cyan")
    table.add_column("Operation")
    table.add_column("Average Time (ms)", justify="right")

    table.add_row(
        "Reference",
        "Report + $lookup → Threat",
        f"{reference_average:.4f}"
    )

    table.add_row(
        "Embedded",
        "Report + embedded threat",
        f"{embedded_average:.4f}"
    )

    console.print(table)

    return reference_average, embedded_average


# ------------------------------------------------------------
# BSON size comparison
# ------------------------------------------------------------

def run_bson_comparison(
    reference_reports,
    embedded_reports
):
    """Compare report BSON size between both designs."""

    reference_size = get_bson_size(
        reference_reports,
        "RPT-001"
    )

    embedded_size = get_bson_size(
        embedded_reports,
        "RPT-001"
    )

    increase = (
        (embedded_size - reference_size)
        / reference_size
    ) * 100

    console.print()
    console.print(
        Panel.fit(
            "[bold]BSON Size Comparison for RPT-001[/bold]",
            border_style="yellow"
        )
    )

    table = Table(
        title="Reference vs Embedded BSON Size",
        show_lines=True
    )

    table.add_column("Design", style="cyan")
    table.add_column("BSON Size", justify="right")

    table.add_row(
        "Reference",
        format_bytes(reference_size)
    )

    table.add_row(
        "Embedded",
        format_bytes(embedded_size)
    )

    console.print(table)

    console.print(
        f"\n  BSON size change: "
        f"{increase:+.2f}%"
    )


# ------------------------------------------------------------
# Update complexity demonstration
# ------------------------------------------------------------

def run_update_comparison(
    embedded_reports,
    redesign_threats
):
    """
    Demonstrate why independent updates can become harder with
    embedding.
    """

    # Count how many reports use the selected threat.
    report_count = embedded_reports.count_documents(
        {
            "embedded_threat.threat_id": SELECTED_THREAT_ID
        }
    )

    console.print()
    console.print(
        Panel.fit(
            "[bold]Update Complexity Comparison[/bold]",
            border_style="yellow"
        )
    )

    # Reference design:
    # A single threat document can be updated once.
    reference_result = redesign_threats.update_one(
        {
            "threat_id": SELECTED_THREAT_ID
        },
        {
            "$set": {
                "severity": "High",
                "demo_update": "2026-09-30"
            }
        }
    )

    # Embedded design:
    # Every report containing the embedded copy needs updating.
    embedded_result = embedded_reports.update_many(
        {
            "embedded_threat.threat_id": SELECTED_THREAT_ID
        },
        {
            "$set": {
                "embedded_threat.severity": "High",
                "embedded_threat.demo_update": "2026-09-30"
            }
        }
    )

    table = Table(
        title="Update Work",
        show_lines=True
    )

    table.add_column("Design", style="cyan")
    table.add_column("Documents Matched", justify="right")
    table.add_column("Interpretation")

    table.add_row(
        "Reference",
        str(reference_result.matched_count),
        "One shared threat document is updated."
    )

    table.add_row(
        "Embedded",
        str(embedded_result.matched_count),
        (
            "Every report containing the embedded "
            "threat copy must be updated."
        )
    )

    console.print(table)

    console.print(
        "\n  This demonstrates the main tradeoff:"
    )

    console.print(
        "  Embedded data can simplify reads, but repeated "
        "copies make independent updates harder."
    )


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():
    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]Lab 7.1 — Try It Yourself[/bold cyan]\n"
            "Redesign Report → Threat as an Embedded Relationship",
            border_style="cyan"
        )
    )

    client = None

    try:
        data = load_seed_data()

        threat_map = {
            threat["threat_id"]: threat
            for threat in data["threats"]
        }

        selected_threat = threat_map.get(
            SELECTED_THREAT_ID
        )

        if selected_threat is None:
            raise ValueError(
                f"Threat {SELECTED_THREAT_ID} "
                "does not exist in the dataset."
            )

        client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=5000
        )

        client.admin.command("ping")

        db = client[MONGO_DB]

        console.print(
            f"[OK] Connected to MongoDB at {MONGO_URI}"
        )

        (
            reference_reports,
            embedded_reports,
            redesign_threats
        ) = prepare_designs(db, data)

        print_schema_decision(selected_threat)

        reference_count = reference_reports.count_documents(
            {
                "threat_ids": SELECTED_THREAT_ID
            }
        )

        embedded_count = embedded_reports.count_documents(
            {
                "embedded_threat.threat_id": SELECTED_THREAT_ID
            }
        )

        console.print()
        console.print(
            f"  Reports referencing {SELECTED_THREAT_ID}: "
            f"{reference_count}"
        )

        console.print(
            f"  Reports embedding {SELECTED_THREAT_ID}: "
            f"{embedded_count}"
        )

        # Run the actual query comparison.
        run_query_comparison(
            reference_reports,
            embedded_reports,
            redesign_threats
        )

        # Compare BSON size.
        run_bson_comparison(
            reference_reports,
            embedded_reports
        )

        # Demonstrate update tradeoff.
        run_update_comparison(
            embedded_reports,
            redesign_threats
        )

        console.print()
        console.print(
            Panel.fit(
                "[bold green]7.1 Embedded Redesign Complete[/bold green]",
                border_style="green"
            )
        )

    except Exception as error:
        console.print(
            f"[bold red][ERROR][/bold red]\n{error}"
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