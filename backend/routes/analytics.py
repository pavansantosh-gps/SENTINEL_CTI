from flask import Blueprint, jsonify

from database import (
    iocs_collection,
    threats_collection,
    reports_collection,
    security_reports_collection,
    working_set_collection
)


analytics_bp = Blueprint(
    "analytics",
    __name__,
    url_prefix="/api/analytics"
)


@analytics_bp.route("/overview", methods=["GET"])
def overview():
    """Return main dashboard statistics."""

    return jsonify({
        "success": True,
        "data": {
            "iocs": iocs_collection.count_documents({}),
            "threats": threats_collection.count_documents({}),
            "cti_reports": reports_collection.count_documents({}),
            "security_reports": security_reports_collection.count_documents({}),
            "working_set_documents": working_set_collection.count_documents({})
        }
    })


@analytics_bp.route("/iocs-by-type", methods=["GET"])
def iocs_by_type():
    """Count IOCs by type."""

    pipeline = [
        {
            "$group": {
                "_id": "$type",
                "count": {"$sum": 1}
            }
        },
        {
            "$sort": {
                "count": -1
            }
        }
    ]

    results = list(iocs_collection.aggregate(pipeline))

    return jsonify({
        "success": True,
        "data": [
            {
                "type": item["_id"],
                "count": item["count"]
            }
            for item in results
        ]
    })


@analytics_bp.route("/threats-by-severity", methods=["GET"])
def threats_by_severity():
    """Count threats by severity."""

    pipeline = [
        {
            "$group": {
                "_id": "$severity",
                "count": {"$sum": 1}
            }
        },
        {
            "$sort": {
                "count": -1
            }
        }
    ]

    results = list(threats_collection.aggregate(pipeline))

    return jsonify({
        "success": True,
        "data": [
            {
                "severity": item["_id"],
                "count": item["count"]
            }
            for item in results
        ]
    })


@analytics_bp.route("/reports-by-year", methods=["GET"])
def reports_by_year():
    """Count security reports by year."""

    pipeline = [
        {
            "$group": {
                "_id": "$year",
                "count": {"$sum": 1}
            }
        },
        {
            "$sort": {
                "_id": 1
            }
        }
    ]

    results = list(security_reports_collection.aggregate(pipeline))

    return jsonify({
        "success": True,
        "data": [
            {
                "year": item["_id"],
                "count": item["count"]
            }
            for item in results
        ]
    })


@analytics_bp.route("/reports-by-category", methods=["GET"])
def reports_by_category():
    """Count security reports by category."""

    pipeline = [
        {
            "$group": {
                "_id": "$category",
                "count": {"$sum": 1}
            }
        },
        {
            "$sort": {
                "count": -1
            }
        }
    ]

    results = list(security_reports_collection.aggregate(pipeline))

    return jsonify({
        "success": True,
        "data": [
            {
                "category": item["_id"],
                "count": item["count"]
            }
            for item in results
        ]
    })