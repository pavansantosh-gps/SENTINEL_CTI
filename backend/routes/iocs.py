from flask import Blueprint, jsonify, request
from database import iocs_collection


ioc_bp = Blueprint(
    "iocs",
    __name__,
    url_prefix="/api/iocs"
)


def clean_document(document):
    """Convert MongoDB document into JSON-safe data."""
    document["_id"] = str(document["_id"])
    return document


@ioc_bp.route("", methods=["GET"])
def get_iocs():
    """
    Get IOC records with optional search and filters.

    Examples:
    /api/iocs
    /api/iocs?search=example.com
    /api/iocs?type=IP
    /api/iocs?confidence=High
    """

    search = request.args.get("search", "").strip()
    ioc_type = request.args.get("type", "").strip()
    confidence = request.args.get("confidence", "").strip()
    category = request.args.get("category", "").strip()

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
            {"indicator": {"$regex": search, "$options": "i"}},
            {"category": {"$regex": search, "$options": "i"}},
            {"type": {"$regex": search, "$options": "i"}},
            {"confidence": {"$regex": search, "$options": "i"}},
        ]

    # Filters
    if ioc_type:
        query["type"] = {
            "$regex": f"^{ioc_type}$",
            "$options": "i"
        }

    if confidence:
        query["confidence"] = {
            "$regex": f"^{confidence}$",
            "$options": "i"
        }

    if category:
        query["category"] = {
            "$regex": category,
            "$options": "i"
        }

    total = iocs_collection.count_documents(query)

    documents = (
        iocs_collection
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


@ioc_bp.route("/<ioc_id>", methods=["GET"])
def get_ioc(ioc_id):
    """Get one IOC by IOC ID."""

    document = iocs_collection.find_one({
        "ioc_id": ioc_id
    })

    if not document:
        return jsonify({
            "success": False,
            "message": "IOC not found"
        }), 404

    return jsonify({
        "success": True,
        "data": clean_document(document)
    })