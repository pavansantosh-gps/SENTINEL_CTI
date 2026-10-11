from flask import Blueprint, jsonify, request

from services.classification import classify_threat


classification_bp = Blueprint(
    "classification",
    __name__,
    url_prefix="/api/classify"
)


@classification_bp.route("", methods=["POST"])
def classify():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "success": False,
            "message": "Request body must contain JSON data."
        }), 400

    text = str(data.get("text", "")).strip()
    ioc_type = data.get("ioc_type")

    if not text:
        return jsonify({
            "success": False,
            "message": "Text is required."
        }), 400

    result = classify_threat(
        text=text,
        ioc_type=ioc_type
    )

    return jsonify({
        "success": True,
        "input": {
            "text": text,
            "ioc_type": ioc_type
        },
        "result": result
    })