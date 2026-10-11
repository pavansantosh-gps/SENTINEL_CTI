from flask import Blueprint, jsonify

from services.cache_monitor import get_working_set_metrics


monitoring_bp = Blueprint(
    "monitoring",
    __name__,
    url_prefix="/api/monitoring"
)


@monitoring_bp.route("", methods=["GET"])
def monitoring():
    """Return current working-set and WiredTiger cache metrics."""

    try:
        result = get_working_set_metrics()

        return jsonify({
            "success": True,
            "data": result
        })

    except Exception as error:
        return jsonify({
            "success": False,
            "message": str(error)
        }), 500