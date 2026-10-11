from flask import Blueprint, jsonify

from services.schema_analysis import get_schema_analysis


schema_bp = Blueprint(
    "schema",
    __name__,
    url_prefix="/api/schema"
)


@schema_bp.route("", methods=["GET"])
def schema_analysis():
    """Return Lab 7.1 schema analysis and BSON statistics."""

    try:
        result = get_schema_analysis()

        return jsonify({
            "success": True,
            "data": result
        })

    except Exception as error:
        return jsonify({
            "success": False,
            "message": str(error)
        }), 500