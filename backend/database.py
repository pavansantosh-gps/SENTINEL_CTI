"""
SENTINEL CTI
Database connection and collection helpers.
"""

import os

from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError


# Load variables from .env
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "sentinel_cti")


# Create MongoDB client
client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=5000
)

# Select database
db = client[MONGO_DB]


# Collections
sources_collection = db["sources"]
threats_collection = db["threats"]
iocs_collection = db["iocs"]
reports_collection = db["reports"]
security_reports_collection = db["security_reports"]
working_set_collection = db["working_set_reports"]


def check_connection():
    """Check whether MongoDB is reachable."""
    try:
        client.admin.command("ping")
        return True
    except (ConnectionFailure, ServerSelectionTimeoutError):
        return False


def get_database_stats():
    """Return document counts for SENTINEL CTI collections."""
    return {
        "sources": sources_collection.count_documents({}),
        "threats": threats_collection.count_documents({}),
        "iocs": iocs_collection.count_documents({}),
        "reports": reports_collection.count_documents({}),
        "security_reports": security_reports_collection.count_documents({}),
        "working_set": working_set_collection.count_documents({}),
    }


def close_connection():
    """Close MongoDB connection."""
    client.close()