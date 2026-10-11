"""
SENTINEL CTI
Lab 7.1 schema analysis service.
"""

from database import reports_collection


DOCUMENT_LIMIT = 16 * 1024 * 1024


SCHEMA_DECISIONS = [
    {
        "relationship": "Report → Source",
        "strategy": "REFERENCE",
        "reason": "Sources can be shared by many reports and maintained independently."
    },
    {
        "relationship": "Report → Threat",
        "strategy": "REFERENCE",
        "reason": "Threat entities are reusable and may be associated with multiple reports."
    },
    {
        "relationship": "Report → IOC",
        "strategy": "REFERENCE",
        "reason": "IOCs are reusable intelligence entities that should not be duplicated."
    },
    {
        "relationship": "Report → Tags",
        "strategy": "EMBED",
        "reason": "Tags are small report-specific values and are naturally stored inside the report."
    },
    {
        "relationship": "Report → Classification",
        "strategy": "EMBED",
        "reason": "Classification describes the report itself and is read together with it."
    },
    {
        "relationship": "Report → Observations",
        "strategy": "EMBED",
        "reason": "Observations are report-specific details that are normally accessed with the report."
    }
]


def get_schema_decisions():
    """Return the documented embedding/reference decisions."""

    return SCHEMA_DECISIONS


def get_bson_statistics():
    """
    Calculate report BSON sizes using MongoDB's $bsonSize
    aggregation expression.
    """

    pipeline = [
        {
            "$project": {
                "_id": 1,
                "bson_size": {
                    "$bsonSize": "$$ROOT"
                }
            }
        },
        {
            "$group": {
                "_id": None,
                "average_size": {"$avg": "$bson_size"},
                "minimum_size": {"$min": "$bson_size"},
                "maximum_size": {"$max": "$bson_size"},
                "document_count": {"$sum": 1}
            }
        }
    ]

    result = list(reports_collection.aggregate(pipeline))

    if not result:
        return {
            "document_count": 0,
            "average_size": 0,
            "minimum_size": 0,
            "maximum_size": 0,
            "document_limit": DOCUMENT_LIMIT,
            "largest_percent_of_limit": 0
        }

    stats = result[0]

    maximum_size = stats["maximum_size"]

    return {
        "document_count": stats["document_count"],
        "average_size": round(stats["average_size"], 2),
        "minimum_size": stats["minimum_size"],
        "maximum_size": maximum_size,
        "document_limit": DOCUMENT_LIMIT,
        "largest_percent_of_limit": round(
            (maximum_size / DOCUMENT_LIMIT) * 100,
            5
        )
    }


def get_schema_analysis():
    """Return complete Lab 7.1 schema analysis."""

    bson_stats = get_bson_statistics()

    return {
        "schema_decisions": get_schema_decisions(),
        "bson_statistics": bson_stats,
        "status": (
            "SAFE"
            if bson_stats["maximum_size"] < DOCUMENT_LIMIT
            else "LIMIT EXCEEDED"
        )
    }