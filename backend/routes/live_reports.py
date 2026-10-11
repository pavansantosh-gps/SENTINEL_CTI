import json
import os
from flask import Blueprint, jsonify

live_reports_bp = Blueprint(
    "live_reports",
    __name__,
    url_prefix="/api/live-reports"
)

LOG_FILE = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "data",
        "live_monitor_log.jsonl"
    )
)


def read_latest_records(limit=10):
    """
    Read the most recent records from the live monitor JSONL file.
    """
    if not os.path.exists(LOG_FILE):
        return []

    records = []

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)

                if isinstance(record, dict):
                    records.append(record)

            except json.JSONDecodeError:
                continue

    return records[-limit:]


def normalize_record(record):
    """
    Convert the real live_monitor_log.jsonl structure
    into a frontend-friendly format.
    """

    source = record.get("source", {})
    random_reads = record.get("random_reads", {})

    source_changed = source.get("changed", False)
    source_report_count = source.get("source_report_count", 0)
    database_report_count = source.get("database_report_count", 0)
    new_report_count = source.get("new_report_count", 0)
    new_reports = source.get("new_reports", [])

    if source_changed:
        source_status = "Source updated"
    else:
        source_status = "Source unchanged"

    if new_report_count > 0:
        report_status = f"{new_report_count} new report(s) detected"
    else:
        report_status = "No new reports detected"

    return {
        "timestamp": record.get("timestamp_utc"),

        "source_status": source_status,
        "report_status": report_status,

        "source_report_count": source_report_count,
        "database_report_count": database_report_count,
        "new_report_count": new_report_count,
        "new_reports": new_reports,

        "random_reads": {
            "requested_reads": random_reads.get("requested_reads", 0),
            "documents_read": random_reads.get("documents_read", 0),
            "elapsed_seconds": random_reads.get("elapsed_seconds", 0),
            "reads_per_second": random_reads.get("reads_per_second", 0)
        },

        "cache_fill_percent": record.get(
            "cache_fill_percent",
            0
        ),

        "derived_read_residency_estimate_percent": record.get(
            "derived_read_residency_estimate_percent",
            0
        ),

        "cache_before": record.get("cache_before", {}),
        "cache_after": record.get("cache_after", {})
    }


@live_reports_bp.route("", methods=["GET"])
def get_live_reports():
    """
    Return the latest live monitoring record and recent history.
    """

    try:
        records = read_latest_records(10)

        normalized_records = [
            normalize_record(record)
            for record in records
        ]

        latest = (
            normalized_records[-1]
            if normalized_records
            else None
        )

        return jsonify({
            "success": True,
            "data": {
                "log_file_exists": os.path.exists(LOG_FILE),
                "record_count": len(normalized_records),
                "latest": latest,
                "history": normalized_records
            }
        })

    except Exception as error:
        return jsonify({
            "success": False,
            "error": str(error)
        }), 500