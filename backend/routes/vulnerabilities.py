from flask import Blueprint, jsonify, request

from database import db


# =============================================================================
# BLUEPRINT
# =============================================================================

vulnerabilities_bp = Blueprint(
    "vulnerabilities",
    __name__,
    url_prefix="/api/vulnerabilities"
)


# =============================================================================
# GET ALL VULNERABILITY RECORDS
# =============================================================================

@vulnerabilities_bp.route("", methods=["GET"])
def get_vulnerabilities():
    """
    Return all consolidated vulnerability intelligence records.
    """

    collection = db["vulnerability_intelligence"]

    cve = request.args.get("cve")

    # ---------------------------------------------------------
    # Search by CVE
    # ---------------------------------------------------------

    if cve:

        document = collection.find_one(
            {
                "cve_id": cve.upper()
            },
            {
                "_id": 0
            }
        )

        if document is None:

            return jsonify({
                "success": False,
                "message": "Vulnerability not found",
                "data": None
            }), 404

        return jsonify({
            "success": True,
            "data": document
        })

    # ---------------------------------------------------------
    # Return all records
    # ---------------------------------------------------------

    documents = list(
        collection.find(
            {},
            {
                "_id": 0
            }
        ).sort(
            "consolidated_at",
            -1
        )
    )

    return jsonify({
        "success": True,
        "count": len(documents),
        "data": documents
    })


# =============================================================================
# GET ONE VULNERABILITY BY CVE
# =============================================================================

@vulnerabilities_bp.route("/<cve_id>", methods=["GET"])
def get_vulnerability(cve_id):
    """
    Return one consolidated vulnerability using its CVE ID.
    """

    collection = db["vulnerability_intelligence"]

    document = collection.find_one(
        {
            "cve_id": cve_id.upper()
        },
        {
            "_id": 0
        }
    )

    if document is None:

        return jsonify({
            "success": False,
            "message": "Vulnerability not found",
            "data": None
        }), 404

    return jsonify({
        "success": True,
        "data": document
    })