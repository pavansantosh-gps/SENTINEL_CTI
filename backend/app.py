import os

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

from database import check_connection, get_database_stats

from routes.iocs import ioc_bp
from routes.threats import threat_bp
from routes.reports import reports_bp
from routes.analytics import analytics_bp
from routes.classification import classification_bp
from routes.schema import schema_bp
from routes.monitoring import monitoring_bp
from routes.live_reports import live_reports_bp
from routes.vulnerabilities import vulnerabilities_bp


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)

CORS(app)


# =========================================================
# FRONTEND LOCATION
# =========================================================

FRONTEND_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "frontend"
    )
)


# =========================================================
# REGISTER API ROUTES
# =========================================================

app.register_blueprint(ioc_bp)
app.register_blueprint(threat_bp)
app.register_blueprint(reports_bp)
app.register_blueprint(analytics_bp)
app.register_blueprint(classification_bp)
app.register_blueprint(schema_bp)
app.register_blueprint(monitoring_bp)
app.register_blueprint(live_reports_bp)
app.register_blueprint(vulnerabilities_bp)



# =========================================================
# FRONTEND ROUTES
# =========================================================

@app.route("/")
def home():
    """Serve the SENTINEL CTI frontend."""

    return send_from_directory(
        FRONTEND_DIR,
        "index.html"
    )


@app.route("/css/<path:filename>")
def serve_css(filename):
    """Serve frontend CSS files."""

    return send_from_directory(
        os.path.join(FRONTEND_DIR, "css"),
        filename
    )


@app.route("/js/<path:filename>")
def serve_js(filename):
    """Serve frontend JavaScript files."""

    return send_from_directory(
        os.path.join(FRONTEND_DIR, "js"),
        filename
    )


# =========================================================
# API HEALTH
# =========================================================

@app.route("/api/health")
def health():
    """Check Flask and MongoDB status."""

    connected = check_connection()

    return jsonify({
        "status": "online" if connected else "offline",
        "mongodb": (
            "connected"
            if connected
            else "disconnected"
        )
    })


# =========================================================
# API STATISTICS
# =========================================================

@app.route("/api/stats")
def stats():
    """Return database collection counts."""

    return jsonify(
        get_database_stats()
    )


# =========================================================
# APPLICATION START
# =========================================================

if __name__ == "__main__":

    print("=" * 60)
    print("SENTINEL CTI — BACKEND SERVER")
    print("=" * 60)

    if check_connection():

        print("[OK] MongoDB connection successful")

    else:

        print("[ERROR] MongoDB connection failed")

    print("[OK] Starting Flask server...")

    print(
        "[INFO] Open http://127.0.0.1:5000 "
        "to open SENTINEL CTI"
    )

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )