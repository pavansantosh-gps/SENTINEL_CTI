from flask import Blueprint, jsonify, request
from database import threats_collection


threat_bp = Blueprint(
    "threats",
    __name__,
    url_prefix="/api/threats"
)


def clean_document(document):
    """Convert MongoDB document into JSON-safe data."""
    document["_id"] = str(document["_id"])
    return document


@threat_bp.route("", methods=["GET"])
def get_threats():
    """
    Get threat intelligence records.

    Examples:
    /api/threats
    /api/threats?search=ransom
    /api/threats?category=Ransomware
    /api/threats?severity=Critical
    """

    search = request.args.get("search", "").strip()
    category = request.args.get("category", "").strip()
    severity = request.args.get("severity", "").strip()

    try:
        limit = min(int(request.args.get("limit", 50)), 100)
        skip = max(int(request.args.get("skip", 0)), 0)
    except ValueError:
        limit = 50
        skip = 0

    query = {}

    # General search
    if search:
        query["$or"] = [
            {"threat_id": {"$regex": search, "$options": "i"}},
            {"name": {"$regex": search, "$options": "i"}},
            {"category": {"$regex": search, "$options": "i"}},
            {"severity": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}},
        ]

    # Category filter
    if category:
        query["category"] = {
            "$regex": f"^{category}$",
            "$options": "i"
        }

    # Severity filter
    if severity:
        query["severity"] = {
            "$regex": f"^{severity}$",
            "$options": "i"
        }

    total = threats_collection.count_documents(query)

    documents = (
        threats_collection
        .find(query)
        .sort("_id", 1)
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


@threat_bp.route("/<threat_id>", methods=["GET"])
def get_threat(threat_id):
    """Get a single threat by threat ID."""

    document = threats_collection.find_one({
        "threat_id": threat_id
    })

    if not document:
        return jsonify({
            "success": False,
            "message": "Threat not found"
        }), 404

    return jsonify({
        "success": True,
        "data": clean_document(document)
    })