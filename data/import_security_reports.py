"""
SENTINEL CTI
Annual Security Reports Dataset Importer

Dataset:
https://github.com/jacobdjwilson/awesome-annual-security-reports/

Purpose:
- Import report metadata from 2020 through 2026.
- Use the current README for recent report metadata.
- Use the repository tree for historical yearly archives.
- Do NOT download PDF files.
- Store report metadata in MongoDB.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import requests
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

COLLECTION_NAME = "security_reports"

REPOSITORY_OWNER = "jacobdjwilson"
REPOSITORY_NAME = "awesome-annual-security-reports"

REPOSITORY_URL = (
    "https://github.com/"
    f"{REPOSITORY_OWNER}/{REPOSITORY_NAME}"
)

RAW_README_URL = (
    f"https://raw.githubusercontent.com/"
    f"{REPOSITORY_OWNER}/{REPOSITORY_NAME}/main/README.md"
)

GITHUB_TREE_API_URL = (
    f"https://api.github.com/repos/"
    f"{REPOSITORY_OWNER}/{REPOSITORY_NAME}/git/trees/main"
)

ARCHIVE_ROOT = "Annual Security Reports"

YEARS = list(range(2020, 2027))

REQUEST_TIMEOUT = 30

OUTPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "security_reports_source.json"
)

console = Console()


# ============================================================
# HTTP helper
# ============================================================

def github_headers() -> dict:
    """Headers for polite public GitHub requests."""

    return {
        "User-Agent": "Sentinel-CTI-Lab7/1.0",
        "Accept": "application/vnd.github+json"
    }


def get_json(url: str) -> dict | list:
    """GET a JSON API endpoint."""

    response = requests.get(
        url,
        headers=github_headers(),
        timeout=REQUEST_TIMEOUT
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# Current README parser
# ============================================================

def fetch_current_readme() -> str:
    """Fetch the current public repository README."""

    console.print(
        "[cyan]Fetching current repository README...[/cyan]"
    )

    response = requests.get(
        RAW_README_URL,
        headers=github_headers(),
        timeout=REQUEST_TIMEOUT
    )

    response.raise_for_status()

    console.print(
        f"[green][OK] README downloaded "
        f"({len(response.text):,} characters)[/green]"
    )

    return response.text


def parse_current_readme(readme: str) -> list[dict]:
    """
    Parse the current README.

    The README organizes the newest report versions under:
    Analysis Reports
    Survey Reports

    and then category headings.
    """

    reports = []

    current_report_type: str | None = None
    current_category: str | None = None

    pattern = re.compile(
        r"""
        ^-\s*
        \[(?P<organization>[^\]]+)\]
        \((?P<source_url>[^)]+)\)
        \s*-\s*
        \[(?P<title>[^\]]+)\]
        \((?P<report_path>[^)]+)\)
        \s*\((?P<year>\d{4})\)
        (?:\s*-\s*(?P<description>.*))?
        $
        """,
        re.VERBOSE
    )

    for raw_line in readme.splitlines():
        line = raw_line.strip()

        if line == "## Analysis Reports":
            current_report_type = "Analysis"
            current_category = None
            continue

        if line == "## Survey Reports":
            current_report_type = "Survey"
            current_category = None
            continue

        if (
            line.startswith("## ")
            and line not in {
                "## Analysis Reports",
                "## Survey Reports"
            }
        ):
            current_report_type = None
            current_category = None
            continue

        if line.startswith("### ") and current_report_type:
            current_category = line[4:].strip()
            continue

        if (
            current_report_type
            and current_category
            and line.startswith("- [")
        ):
            match = pattern.match(line)

            if not match:
                continue

            organization = match.group(
                "organization"
            ).strip()

            title = match.group(
                "title"
            ).strip()

            source_url = match.group(
                "source_url"
            ).strip()

            report_path = match.group(
                "report_path"
            ).strip()

            year = int(
                match.group("year")
            )

            description = (
                match.group("description") or ""
            ).strip()

            repository_report_url = (
                f"{REPOSITORY_URL}/blob/main/"
                f"{quote(report_path, safe='/')}"
            )

            reports.append(
                {
                    "organization": organization,
                    "title": title,
                    "year": year,
                    "report_type": current_report_type,
                    "category": current_category,
                    "source_url": source_url,
                    "repository_report_url": repository_report_url,
                    "description": description,
                    "dataset_source": (
                        "awesome-annual-security-reports"
                    ),
                    "metadata_method": "current_readme"
                }
            )

    return reports


# ============================================================
# Historical repository tree
# ============================================================

def fetch_repository_tree() -> list[dict]:
    """
    Fetch the complete repository tree once.

    We use this instead of downloading every PDF.
    """

    console.print(
        "[cyan]Fetching repository file tree...[/cyan]"
    )

    url = (
        GITHUB_TREE_API_URL
        + "?recursive=1"
    )

    payload = get_json(url)

    if not isinstance(payload, dict):
        raise RuntimeError(
            "Unexpected GitHub tree response."
        )

    tree = payload.get("tree", [])

    if not tree:
        raise RuntimeError(
            "GitHub repository tree was empty."
        )

    console.print(
        f"[green][OK] Repository tree contains "
        f"{len(tree):,} entries.[/green]"
    )

    return tree


def normalize_title(filename: str, year: int) -> str:
    """
    Convert an archive filename into a readable title.

    This is used only for historical files where the current
    README no longer lists the older edition.
    """

    name = Path(filename).stem

    # Remove the year at the end when present.
    name = re.sub(
        rf"[-_ ]?{year}$",
        "",
        name,
        flags=re.IGNORECASE
    )

    # Convert common separators.
    name = re.sub(
        r"[-_]+",
        " ",
        name
    )

    # Normalize repeated whitespace.
    name = re.sub(
        r"\s+",
        " ",
        name
    ).strip()

    return name


def infer_organization(filename: str) -> str:
    """
    Infer a source/organization label from the beginning of the
    repository filename.

    This is explicitly labelled as inferred metadata.
    """

    stem = Path(filename).stem

    # Remove trailing year.
    stem = re.sub(
        r"[-_ ]?\d{4}$",
        "",
        stem
    )

    parts = re.split(
        r"[-_]+",
        stem
    )

    if not parts:
        return "Unknown"

    # Take the first meaningful segment(s).
    organization = parts[0].strip()

    if not organization:
        organization = "Unknown"

    return organization


def build_historical_reports(
    tree: list[dict]
) -> list[dict]:
    """
    Build report metadata for 2020-2024 from the yearly archive.

    We use PDF files as the primary archive records.

    Historical records are marked explicitly so that the final
    application can distinguish them from metadata parsed from
    the current README.
    """

    reports = []

    for year in YEARS:
        if year in (2025, 2026):
            continue

        year_prefix = (
            f"{ARCHIVE_ROOT}/{year}/"
        )

        year_files = [
            entry
            for entry in tree
            if entry.get("type") == "blob"
            and entry.get("path", "").startswith(
                year_prefix
            )
        ]

        pdf_files = [
            entry
            for entry in year_files
            if entry["path"].lower().endswith(".pdf")
        ]

        console.print(
            f"  {year}: "
            f"{len(pdf_files):,} PDF records found"
        )

        for entry in pdf_files:
            path = entry["path"]

            filename = Path(path).name

            title = normalize_title(
                filename,
                year
            )

            organization = infer_organization(
                filename
            )

            repository_report_url = (
                f"{REPOSITORY_URL}/blob/main/"
                f"{quote(path, safe='/')}"
            )

            source_url = None

            reports.append(
                {
                    "organization": organization,
                    "title": title,
                    "year": year,
                    "report_type": "Historical Archive",
                    "category": "Historical Security Report",
                    "source_url": source_url,
                    "repository_report_url": repository_report_url,
                    "description": (
                        "Historical annual security report "
                        "from the repository archive."
                    ),
                    "dataset_source": (
                        "awesome-annual-security-reports"
                    ),
                    "metadata_method": (
                        "yearly_repository_archive"
                    )
                }
            )

    return reports


# ============================================================
# Deduplication and merge
# ============================================================

def merge_reports(
    current_reports: list[dict],
    historical_reports: list[dict]
) -> list[dict]:
    """
    Merge current README records with historical archive
    records and deduplicate by repository URL.
    """

    combined = {}

    # Historical first.
    for report in historical_reports:
        combined[
            report["repository_report_url"]
        ] = report

    # Current README records take precedence because they contain
    # richer category/source/description metadata.
    for report in current_reports:
        combined[
            report["repository_report_url"]
        ] = report

    return list(
        combined.values()
    )


# ============================================================
# MongoDB
# ============================================================

def import_to_mongodb(
    reports: list[dict]
):
    """Replace the security_reports collection."""

    client = MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=5000
    )

    client.admin.command("ping")

    db = client[MONGO_DB]

    if COLLECTION_NAME in db.list_collection_names():
        db.drop_collection(
            COLLECTION_NAME
        )

    collection = db[
        COLLECTION_NAME
    ]

    imported_at = datetime.now(
        timezone.utc
    )

    for report in reports:
        report["imported_at"] = imported_at

    if reports:
        collection.insert_many(
            reports,
            ordered=False
        )

    # Search/filter indexes used by the application.
    collection.create_index(
        [("year", -1)],
        name="idx_year_desc"
    )

    collection.create_index(
        [("category", 1), ("year", -1)],
        name="idx_category_year"
    )

    collection.create_index(
        [("organization", 1)],
        name="idx_organization"
    )

    collection.create_index(
        [("report_type", 1)],
        name="idx_report_type"
    )

    collection.create_index(
        [("title", "text"), ("description", "text")],
        name="idx_report_text"
    )

    collection.create_index(
        [("repository_report_url", 1)],
        unique=True,
        name="idx_report_url_unique"
    )

    return client, collection


# ============================================================
# Save reproducible source snapshot
# ============================================================

def save_snapshot(
    reports: list[dict]
):
    """Save the exact metadata imported into MongoDB."""

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    payload = {
        "repository": REPOSITORY_URL,
        "years": YEARS,
        "fetched_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "report_count": len(reports),
        "reports": reports
    }

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            payload,
            file,
            indent=2,
            ensure_ascii=False,
            default=str
        )

    console.print(
        "[green][OK] Source snapshot saved:[/green]"
    )

    console.print(
        f"     {OUTPUT_FILE}"
    )


# ============================================================
# Display statistics
# ============================================================

def display_summary(
    reports: list[dict],
    collection
):
    """Show the imported dataset summary."""

    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]Security Reports — 2020 to 2026[/bold cyan]",
            border_style="cyan"
        )
    )

    by_year = {}

    for report in reports:
        year = report["year"]

        by_year[year] = (
            by_year.get(year, 0)
            + 1
        )

    table = Table(
        title="Reports by Year",
        show_lines=True
    )

    table.add_column(
        "Year",
        style="cyan"
    )

    table.add_column(
        "Reports",
        justify="right"
    )

    for year in YEARS:
        table.add_row(
            str(year),
            str(by_year.get(year, 0))
        )

    table.add_row(
        "[bold]TOTAL[/bold]",
        f"[bold]{len(reports):,}[/bold]"
    )

    console.print(table)

    # Current vs historical.
    current_count = sum(
        1
        for report in reports
        if report["metadata_method"]
        == "current_readme"
    )

    historical_count = sum(
        1
        for report in reports
        if report["metadata_method"]
        == "yearly_repository_archive"
    )

    console.print()
    console.print(
        f"  Current README records : "
        f"{current_count:,}"
    )

    console.print(
        f"  Historical archive records : "
        f"{historical_count:,}"
    )

    console.print()

    sample_table = Table(
        title="Sample Historical Records",
        show_lines=True
    )

    sample_table.add_column(
        "Year",
        justify="right"
    )

    sample_table.add_column(
        "Organization"
    )

    sample_table.add_column(
        "Title",
        style="cyan"
    )

    historical_samples = [
        report
        for report in reports
        if report["metadata_method"]
        == "yearly_repository_archive"
    ][:8]

    for report in historical_samples:
        sample_table.add_row(
            str(report["year"]),
            report["organization"][:25],
            report["title"][:50]
        )

    console.print(
        sample_table
    )

    console.print()

    console.print(
        f"[green][OK] MongoDB collection "
        f"'{COLLECTION_NAME}' contains "
        f"{collection.count_documents({}):,} documents.[/green]"
    )


# ============================================================
# Main
# ============================================================

def main():
    """Run the complete 2020-2026 report import."""

    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]SENTINEL CTI[/bold cyan]\n"
            "Annual Security Reports — 2020 to 2026",
            border_style="cyan"
        )
    )

    client = None

    try:
        # -----------------------------------------------
        # Current README
        # -----------------------------------------------

        readme = fetch_current_readme()

        current_reports = parse_current_readme(
            readme
        )

        console.print(
            f"[OK] Current README records: "
            f"{len(current_reports):,}"
        )

        # -----------------------------------------------
        # Historical archive
        # -----------------------------------------------

        tree = fetch_repository_tree()

        historical_reports = build_historical_reports(
            tree
        )

        # -----------------------------------------------
        # Merge
        # -----------------------------------------------

        reports = merge_reports(
            current_reports,
            historical_reports
        )

        if not reports:
            raise RuntimeError(
                "No security report records were collected."
            )

        console.print()
        console.print(
            f"[OK] Combined report records: "
            f"{len(reports):,}"
        )

        # -----------------------------------------------
        # MongoDB
        # -----------------------------------------------

        client, collection = import_to_mongodb(
            reports
        )

        console.print(
            f"[OK] Connected to MongoDB at "
            f"{MONGO_URI}"
        )

        console.print(
            f"[OK] Database: {MONGO_DB}"
        )

        # -----------------------------------------------
        # Display
        # -----------------------------------------------

        display_summary(
            reports,
            collection
        )

        # -----------------------------------------------
        # Reproducible snapshot
        # -----------------------------------------------

        save_snapshot(
            reports
        )

        console.print()
        console.print(
            Panel.fit(
                "[bold green]2020–2026 Import Complete[/bold green]",
                border_style="green"
            )
        )

    except requests.RequestException as error:
        console.print(
            "[bold red][ERROR] GitHub request failed[/bold red]"
        )
        console.print(error)
        raise

    except PyMongoError as error:
        console.print(
            "[bold red][ERROR] MongoDB error[/bold red]"
        )
        console.print(error)
        raise

    except Exception as error:
        console.print(
            "[bold red][ERROR] Unexpected error[/bold red]"
        )
        console.print(error)
        raise

    finally:
        if client is not None:
            client.close()
            console.print(
                "[OK] MongoDB connection closed."
            )


if __name__ == "__main__":
    main()  