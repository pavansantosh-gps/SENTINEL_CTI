from flask import Blueprint, jsonify, request
from database import security_reports_collection


reports_bp = Blueprint(
    "reports",
    __name__,
    url_prefix="/api/reports"
)


def clean_document(document):
    """Convert MongoDB document into JSON-safe data."""
    document["_id"] = str(document["_id"])
    return document


@reports_bp.route("", methods=["GET"])
def get_reports():
    """
    Get security reports with search and filters.

    Examples:
    /api/reports
    /api/reports?search=cloud
    /api/reports?year=2025
    /api/reports?category=Threat Intelligence
    /api/reports?organization=IBM
    """

    search = request.args.get("search", "").strip()
    year = request.args.get("year", "").strip()
    category = request.args.get("category", "").strip()
    organization = request.args.get("organization", "").strip()
    report_type = request.args.get("report_type", "").strip()

    try:
        limit = min(int(request.args.get("limit", 20)), 100)
        skip = max(int(request.args.get("skip", 0)), 0)
    except ValueError:
        limit = 20
        skip = 0

    query = {}

    # General text search
    if search:
        query["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"organization": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}},
            {"category": {"$regex": search, "$options": "i"}},
            {"report_type": {"$regex": search, "$options": "i"}},
        ]

    # Year filter
    if year:
        try:
            query["year"] = int(year)
        except ValueError:
            return jsonify({
                "success": False,
                "message": "Year must be a number"
            }), 400

    # Category filter
    if category:
        query["category"] = {
            "$regex": category,
            "$options": "i"
        }

    # Organization filter
    if organization:
        query["organization"] = {
            "$regex": organization,
            "$options": "i"
        }

    # Report type filter
    if report_type:
        query["report_type"] = {
            "$regex": report_type,
            "$options": "i"
        }

    total = security_reports_collection.count_documents(query)

    documents = (
        security_reports_collection
        .find(query)
        .sort("year", -1)
        .skip(skip)
        .limit(limit)
    )

    results = [clean_document(doc) for doc in documents]

    return jsonify({
        "success": True,
        "count": len(results),
        "total": total,
        "skip": skip,
        "limit": limit,
        "data": results
    })


@reports_bp.route("/years", methods=["GET"])
def get_years():
    """Return available report years with document counts."""

    pipeline = [
        {
            "$group": {
                "_id": "$year",
                "count": {"$sum": 1}
            }
        },
        {
            "$sort": {
                "_id": -1
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


@reports_bp.route("/<report_id>", methods=["GET"])
def get_report(report_id):
    """Get a single security report by repository report URL."""

    document = security_reports_collection.find_one({
        "repository_report_url": report_id
    })

    if not document:
        return jsonify({
            "success": False,
            "message": "Report not found"
        }), 404

    return jsonify({
        "success": True,
        "data": clean_document(document)
    })