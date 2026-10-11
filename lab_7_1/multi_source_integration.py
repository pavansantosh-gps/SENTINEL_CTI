"""
LAB 7.1 - MULTI-SOURCE VULNERABILITY INTEGRATION

Sources:
1. OSV.dev
2. EUVD / ENISA
3. CIRCL Vulnerability-Lookup

Flow:
Three public APIs
        ↓
Common CVE ID
        ↓
Normalize data
        ↓
Consolidate useful fields
        ↓
One MongoDB document
"""

import json
import os
from datetime import datetime, timezone

import requests
from bson import BSON
from dotenv import load_dotenv
from pymongo import MongoClient, ASCENDING


# =============================================================================
# CONFIGURATION
# =============================================================================

load_dotenv()

MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb://localhost:27017"
)

MONGO_DB = os.getenv(
    "MONGO_DB",
    "sentinel_cti"
)

# Common key used to match the same vulnerability across all sources.
CVE_ID = "CVE-2026-22799"

# Public API endpoints.
OSV_URL = f"https://api.osv.dev/v1/vulns/{CVE_ID}"

EUVD_URL = (
    "https://euvdservices.enisa.europa.eu/api/enisaid"
)

CIRCL_URL = (
    f"https://vulnerability.circl.lu/api/vulnerability/{CVE_ID}"
)

HEADERS = {
    "Accept": "application/json",
    "User-Agent": "SENTINEL-CTI/1.0"
}

TIMEOUT = 30


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def fetch_json(url, params=None):
    """
    Fetch JSON data from a public API.

    Returns:
        data, payload_size_in_bytes
    """

    response = requests.get(
        url,
        params=params,
        headers=HEADERS,
        timeout=TIMEOUT
    )

    response.raise_for_status()

    payload_size = len(response.content)

    return response.json(), payload_size


def to_float(value):
    """
    Safely convert a value to float.
    """

    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def unique_list(values):
    """
    Remove duplicate values while preserving order.
    """

    result = []

    for value in values:

        if value is None:
            continue

        value = str(value).strip()

        if value and value not in result:
            result.append(value)

    return result


# =============================================================================
# OSV NORMALIZATION
# =============================================================================

def normalize_osv(data):
    """
    Normalize OSV response into a common structure.
    """

    if not isinstance(data, dict):
        return None

    affected = data.get(
        "affected",
        []
    )

    vendors = []
    products = []

    for item in affected:

        if not isinstance(item, dict):
            continue

        package = item.get(
            "package",
            {}
        )

        if not isinstance(package, dict):
            continue

        package_name = package.get(
            "name"
        )

        ecosystem = package.get(
            "ecosystem"
        )

        if package_name:
            products.append(package_name)

        if ecosystem:
            vendors.append(ecosystem)

    severity = None
    cvss_score = None
    cvss_version = None
    cvss_vector = None

    # Some OSV records contain severity information.
    severity_list = data.get(
        "severity",
        []
    )

    if isinstance(severity_list, list):

        for item in severity_list:

            if not isinstance(item, dict):
                continue

            severity_type = item.get(
                "type"
            )

            score = item.get(
                "score"
            )

            if severity_type:
                cvss_version = severity_type

            if score:
                cvss_vector = score

    database_specific = data.get(
        "database_specific",
        {}
    )

    if isinstance(database_specific, dict):

        severity = database_specific.get(
            "severity"
        )

    references = []

    for item in data.get(
        "references",
        []
    ):

        if not isinstance(item, dict):
            continue

        url = item.get(
            "url"
        )

        if url:
            references.append(url)

    return {
        "cve_id": data.get("id") or CVE_ID,

        "title": (
            data.get("summary")
            or "Untitled Vulnerability"
        ),

        "description": data.get(
            "details"
        ),

        "severity": severity,

        "cvss_score": cvss_score,

        "cvss_version": cvss_version,

        "cvss_vector": cvss_vector,

        "epss": None,

        "vendors": unique_list(vendors),

        "products": unique_list(products),

        "references": unique_list(references)
    }


# =============================================================================
# EUVD NORMALIZATION
# =============================================================================

def normalize_euvd(data, cve_id):
    """
    Normalize EUVD / ENISA response.

    Important:
    EUVD /api/enisaid can provide fields such as:

        enisa_id
        aliases
        baseScore
        baseScoreVersion
        baseScoreVector
        epss
        enisaIdProduct
        enisaIdVendor
        enisaIdVulnerability

    This function extracts those fields and converts them into
    our common format.
    """

    if not data:
        return None

    # -------------------------------------------------------------------------
    # Determine the main EUVD record.
    # -------------------------------------------------------------------------

    if isinstance(data, list):

        if len(data) == 0:
            return None

        record = data[0]

    elif isinstance(data, dict):

        record = data

        # Some API wrappers may place the actual result inside
        # one of these keys.
        for wrapper_key in (
            "data",
            "result",
            "vulnerability",
            "item"
        ):

            possible = record.get(
                wrapper_key
            )

            if isinstance(possible, dict):

                # Only switch when it looks like an actual
                # vulnerability record.
                if (
                    "baseScore" in possible
                    or "enisa_id" in possible
                    or "enisaIdVulnerability" in possible
                    or "aliases" in possible
                ):
                    record = possible
                    break

    else:
        return None

    if not isinstance(record, dict):
        return None

    # -------------------------------------------------------------------------
    # CVE ID
    # -------------------------------------------------------------------------

    cve_found = cve_id

    aliases = record.get(
        "aliases",
        ""
    )

    if isinstance(aliases, str):

        aliases_text = aliases.replace(
            "\\n",
            "\n"
        )

        for value in aliases_text.splitlines():

            value = value.strip()

            if value.upper().startswith("CVE-"):
                cve_found = value
                break

    elif isinstance(aliases, list):

        for value in aliases:

            value = str(value).strip()

            if value.upper().startswith("CVE-"):
                cve_found = value
                break

    # -------------------------------------------------------------------------
    # EUVD ID
    # -------------------------------------------------------------------------

    euvd_id = record.get(
        "enisa_id"
    )

    # Clean newline / whitespace.
    if isinstance(euvd_id, str):
        euvd_id = euvd_id.strip()

    # If the top-level EUVD ID is missing, search inside
    # enisaIdVulnerability.
    if not euvd_id:

        vulnerability_list = record.get(
            "enisaIdVulnerability",
            []
        )

        if isinstance(vulnerability_list, list):

            for item in vulnerability_list:

                if not isinstance(item, dict):
                    continue

                vulnerability = item.get(
                    "vulnerability",
                    {}
                )

                if not isinstance(
                    vulnerability,
                    dict
                ):
                    continue

                nested_id = vulnerability.get(
                    "enisa_id"
                )

                if nested_id:

                    euvd_id = str(
                        nested_id
                    ).strip()

                    break

    # -------------------------------------------------------------------------
    # Vendor extraction
    # -------------------------------------------------------------------------

    vendors = []

    vendor_list = record.get(
        "enisaIdVendor",
        []
    )

    if isinstance(vendor_list, list):

        for item in vendor_list:

            if not isinstance(item, dict):
                continue

            vendor = item.get(
                "vendor",
                {}
            )

            if isinstance(vendor, dict):

                name = vendor.get(
                    "name"
                )

                if name:
                    vendors.append(name)

    # -------------------------------------------------------------------------
    # Product extraction
    # -------------------------------------------------------------------------

    products = []

    product_list = record.get(
        "enisaIdProduct",
        []
    )

    if isinstance(product_list, list):

        for item in product_list:

            if not isinstance(item, dict):
                continue

            product = item.get(
                "product",
                {}
            )

            if isinstance(product, dict):

                name = product.get(
                    "name"
                )

                if name:
                    products.append(name)

    # -------------------------------------------------------------------------
    # References
    # -------------------------------------------------------------------------

    references = record.get(
        "references",
        ""
    )

    if isinstance(references, str):

        references = [
            value.strip()
            for value in references.splitlines()
            if value.strip()
        ]

    elif isinstance(references, list):

        references = [
            str(value).strip()
            for value in references
            if str(value).strip()
        ]

    else:

        references = []

    # -------------------------------------------------------------------------
    # Return normalized EUVD record
    # -------------------------------------------------------------------------

    return {
        "cve_id": cve_found,

        "euvd_id": euvd_id,

        "title": (
            record.get("title")
            or "EUVD Vulnerability Record"
        ),

        "description": (
            record.get("description")
        ),

        "severity": (
            record.get("severity")
        ),

        "cvss_score": to_float(
            record.get("baseScore")
        ),

        "cvss_version": (
            record.get("baseScoreVersion")
        ),

        "cvss_vector": (
            record.get("baseScoreVector")
        ),

        "epss": to_float(
            record.get("epss")
        ),

        "vendors": unique_list(vendors),

        "products": unique_list(products),

        "references": unique_list(references)
    }


# =============================================================================
# CIRCL NORMALIZATION
# =============================================================================

def normalize_circl(data, cve_id):
    """
    Normalize CIRCL Vulnerability-Lookup response.
    """

    if not data:
        return None

    # -------------------------------------------------------------------------
    # Find the main record.
    # -------------------------------------------------------------------------

    if isinstance(data, list):

        if len(data) == 0:
            return None

        record = data[0]

    elif isinstance(data, dict):

        record = data

        for wrapper_key in (
            "data",
            "vulnerability",
            "result"
        ):

            possible = record.get(
                wrapper_key
            )

            if isinstance(possible, dict):

                if (
                    "description" in possible
                    or "cvss" in possible
                    or "id" in possible
                ):
                    record = possible
                    break

    else:
        return None

    if not isinstance(record, dict):
        return None

    # -------------------------------------------------------------------------
    # CVE ID
    # -------------------------------------------------------------------------

    detected_cve = (
        record.get("id")
        or record.get("cve")
        or record.get("cve_id")
        or cve_id
    )

    # -------------------------------------------------------------------------
    # Title
    # -------------------------------------------------------------------------

    title = (
        record.get("title")
        or record.get("summary")
        or record.get("name")
    )

    # -------------------------------------------------------------------------
    # Description
    # -------------------------------------------------------------------------

    description = (
        record.get("description")
        or record.get("details")
        or record.get("summary")
    )

    # -------------------------------------------------------------------------
    # CVSS
    # -------------------------------------------------------------------------

    cvss_score = None
    cvss_version = None
    cvss_vector = None

    cvss = record.get(
        "cvss"
    )

    if isinstance(cvss, dict):

        cvss_score = to_float(
            cvss.get("score")
            or cvss.get("base_score")
            or cvss.get("baseScore")
        )

        cvss_version = (
            cvss.get("version")
            or cvss.get("cvss_version")
        )

        cvss_vector = (
            cvss.get("vector")
            or cvss.get("vectorString")
            or cvss.get("baseScoreVector")
        )

    elif isinstance(cvss, (int, float, str)):

        cvss_score = to_float(
            cvss
        )

    if cvss_score is None:

        cvss_score = to_float(
            record.get("baseScore")
            or record.get("cvss_score")
        )

    if cvss_version is None:

        cvss_version = (
            record.get("baseScoreVersion")
            or record.get("cvss_version")
        )

    if cvss_vector is None:

        cvss_vector = (
            record.get("baseScoreVector")
            or record.get("cvss_vector")
        )

    # -------------------------------------------------------------------------
    # Vendors
    # -------------------------------------------------------------------------

    vendors = []

    vendor_value = record.get(
        "vendor"
    )

    if isinstance(vendor_value, str):

        vendors.append(
            vendor_value
        )

    elif isinstance(vendor_value, dict):

        name = vendor_value.get(
            "name"
        )

        if name:
            vendors.append(name)

    # -------------------------------------------------------------------------
    # Products
    # -------------------------------------------------------------------------

    products = []

    product_value = record.get(
        "product"
    )

    if isinstance(product_value, str):

        products.append(
            product_value
        )

    elif isinstance(product_value, dict):

        name = product_value.get(
            "name"
        )

        if name:
            products.append(name)

    # -------------------------------------------------------------------------
    # References
    # -------------------------------------------------------------------------

    references = record.get(
        "references",
        []
    )

    if isinstance(references, str):

        references = [
            references
        ]

    elif not isinstance(
        references,
        list
    ):

        references = []

    return {
        "cve_id": detected_cve,

        "title": title,

        "description": description,

        "severity": record.get(
            "severity"
        ),

        "cvss_score": cvss_score,

        "cvss_version": cvss_version,

        "cvss_vector": cvss_vector,

        "epss": to_float(
            record.get("epss")
        ),

        "vendors": unique_list(vendors),

        "products": unique_list(products),

        "references": unique_list(
            references
        )
    }


# =============================================================================
# CONSOLIDATION
# =============================================================================

def consolidate_records(
    cve_id,
    osv,
    euvd,
    circl
):
    """
    Combine the useful information from the three normalized sources
    into one MongoDB document.
    """

    records = {
        "OSV": osv,
        "EUVD": euvd,
        "CIRCL": circl
    }

    successful = {
        source: record
        for source, record in records.items()
        if record is not None
    }

    # -------------------------------------------------------------------------
    # Title
    # -------------------------------------------------------------------------

    title = None

    for source in (
        "OSV",
        "EUVD",
        "CIRCL"
    ):

        record = successful.get(
            source
        )

        if record and record.get("title"):

            title = record[
                "title"
            ]

            break

    # -------------------------------------------------------------------------
    # Description
    # -------------------------------------------------------------------------

    description = None

    for source in (
        "OSV",
        "EUVD",
        "CIRCL"
    ):

        record = successful.get(
            source
        )

        if record and record.get(
            "description"
        ):

            description = record[
                "description"
            ]

            break

    # -------------------------------------------------------------------------
    # Severity
    # -------------------------------------------------------------------------

    severity = None

    for source in (
        "EUVD",
        "OSV",
        "CIRCL"
    ):

        record = successful.get(
            source
        )

        if record and record.get(
            "severity"
        ):

            severity = record[
                "severity"
            ]

            break

    # -------------------------------------------------------------------------
    # CVSS
    # -------------------------------------------------------------------------

    cvss_score = None
    cvss_version = None
    cvss_vector = None

    for source in (
        "EUVD",
        "OSV",
        "CIRCL"
    ):

        record = successful.get(
            source
        )

        if not record:
            continue

        if (
            cvss_score is None
            and record.get("cvss_score") is not None
        ):

            cvss_score = record[
                "cvss_score"
            ]

        if (
            cvss_version is None
            and record.get("cvss_version")
        ):

            cvss_version = record[
                "cvss_version"
            ]

        if (
            cvss_vector is None
            and record.get("cvss_vector")
        ):

            cvss_vector = record[
                "cvss_vector"
            ]

    # -------------------------------------------------------------------------
    # EPSS
    # -------------------------------------------------------------------------

    epss = None

    for source in (
        "EUVD",
        "CIRCL",
        "OSV"
    ):

        record = successful.get(
            source
        )

        if (
            record
            and record.get("epss") is not None
        ):

            epss = record[
                "epss"
            ]

            break

    # -------------------------------------------------------------------------
    # Merge vendors and products
    # -------------------------------------------------------------------------

    vendors = []
    products = []

    for record in successful.values():

        vendors.extend(
            record.get(
                "vendors",
                []
            )
        )

        products.extend(
            record.get(
                "products",
                []
            )
        )

    vendors = unique_list(
        vendors
    )

    products = unique_list(
        products
    )

    # -------------------------------------------------------------------------
    # Source provenance
    # -------------------------------------------------------------------------

    source_provenance = []

    # OSV
    if osv is not None:

        source_provenance.append({
            "source": "OSV",

            "record_id": (
                osv.get("cve_id")
                or cve_id
            ),

            "url": (
                f"https://osv.dev/vulnerability/"
                f"{cve_id}"
            )
        })

    # EUVD
    if euvd is not None:

        euvd_id = euvd.get(
            "euvd_id"
        )

        source_provenance.append({
            "source": "EUVD",

            "record_id": (
                euvd_id
                or "UNKNOWN"
            ),

            "url": (
                (
                    "https://euvd.enisa.europa.eu/"
                    "vulnerability/"
                    f"{euvd_id}"
                )
                if euvd_id
                else None
            )
        })

    # CIRCL
    if circl is not None:

        source_provenance.append({
            "source": "CIRCL",

            "record_id": (
                circl.get("cve_id")
                or cve_id
            ),

            "url": (
                f"https://cve.circl.lu/vuln/"
                f"{cve_id}"
            )
        })

    # -------------------------------------------------------------------------
    # Final consolidated document
    # -------------------------------------------------------------------------

    return {
        "cve_id": cve_id,

        "title": title,

        "description": description,

        "severity": severity,

        "cvss": {
            "score": cvss_score,
            "version": cvss_version,
            "vector": cvss_vector
        },

        "epss": epss,

        "vendors": vendors,

        "products": products,

        "source_count": len(
            source_provenance
        ),

        "source_provenance": (
            source_provenance
        ),

        "consolidated_at": (
            datetime.now(
                timezone.utc
            ).isoformat()
        )
    }


# =============================================================================
# MONGODB STORAGE
# =============================================================================

def store_document(document):
    """
    Store exactly one consolidated document per CVE.
    """

    client = MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=5000
    )

    db = client[
        MONGO_DB
    ]

    collection = db[
        "vulnerability_intelligence"
    ]

    # One CVE should correspond to one consolidated document.
    collection.create_index(
        [("cve_id", ASCENDING)],
        unique=True
    )

    result = collection.update_one(
        {
            "cve_id": document[
                "cve_id"
            ]
        },

        {
            "$set": document
        },

        upsert=True
    )

    client.close()

    return result


# =============================================================================
# MAIN PROGRAM
# =============================================================================

def main():

    print("=" * 80)
    print(
        "LAB 7.1 - MULTI-SOURCE VULNERABILITY INTEGRATION"
    )
    print("=" * 80)

    print()
    print(
        f"Common CVE ID : {CVE_ID}"
    )

    print()
    print("Sources:")
    print("1. OSV.dev")
    print("2. EUVD / ENISA")
    print("3. CIRCL Vulnerability-Lookup")

    # =========================================================================
    # STEP 1
    # =========================================================================

    print()
    print("=" * 80)
    print(
        "STEP 1 - FETCHING PUBLIC API DATA"
    )
    print("=" * 80)

    osv_data = None
    euvd_data = None
    circl_data = None

    osv_bytes = 0
    euvd_bytes = 0
    circl_bytes = 0

    # -------------------------------------------------------------------------
    # OSV
    # -------------------------------------------------------------------------

    try:

        osv_data, osv_bytes = fetch_json(
            OSV_URL
        )

        print("[OK] OSV")

        print(
            f"      Payload size: "
            f"{osv_bytes:,} bytes"
        )

    except Exception as error:

        print(
            f"[ERROR] OSV request failed: "
            f"{error}"
        )

        print(
            "[ERROR] OSV"
        )

        print(
            "      Payload size: 0 bytes"
        )

    # -------------------------------------------------------------------------
    # EUVD
    # -------------------------------------------------------------------------

    try:

        euvd_data, euvd_bytes = fetch_json(
            EUVD_URL,
            params={
                "id": CVE_ID
            }
        )

        print("[OK] EUVD")

        print(
            f"      Payload size: "
            f"{euvd_bytes:,} bytes"
        )

    except Exception as error:

        print(
            f"[ERROR] EUVD request failed: "
            f"{error}"
        )

        print(
            "[ERROR] EUVD"
        )

        print(
            "      Payload size: 0 bytes"
        )

    # -------------------------------------------------------------------------
    # CIRCL
    # -------------------------------------------------------------------------

    try:

        circl_data, circl_bytes = fetch_json(
            CIRCL_URL
        )

        print("[OK] CIRCL")

        print(
            f"      Payload size: "
            f"{circl_bytes:,} bytes"
        )

    except Exception as error:

        print(
            f"[ERROR] CIRCL request failed: "
            f"{error}"
        )

        print(
            "[ERROR] CIRCL"
        )

        print(
            "      Payload size: 0 bytes"
        )

    # =========================================================================
    # STEP 2
    # =========================================================================

    print()
    print("=" * 80)
    print(
        "STEP 2 - NORMALIZING SOURCE DATA"
    )
    print("=" * 80)

    osv_normalized = None
    euvd_normalized = None
    circl_normalized = None

    # -------------------------------------------------------------------------
    # OSV
    # -------------------------------------------------------------------------

    if osv_data is not None:

        try:

            osv_normalized = normalize_osv(
                osv_data
            )

            print(
                "[OK] OSV normalized"
            )

        except Exception as error:

            print(
                f"[ERROR] OSV normalization failed: "
                f"{error}"
            )

    else:

        print(
            "[MISS] OSV normalized"
        )

    # -------------------------------------------------------------------------
    # EUVD
    # -------------------------------------------------------------------------

    if euvd_data is not None:

        try:

            euvd_normalized = normalize_euvd(
                euvd_data,
                CVE_ID
            )

            if euvd_normalized is not None:

                print(
                    "[OK] EUVD normalized"
                )

            else:

                print(
                    "[MISS] EUVD normalized"
                )

        except Exception as error:

            print(
                f"[ERROR] EUVD normalization failed: "
                f"{error}"
            )

    else:

        print(
            "[MISS] EUVD normalized"
        )

    # -------------------------------------------------------------------------
    # CIRCL
    # -------------------------------------------------------------------------

    if circl_data is not None:

        try:

            circl_normalized = normalize_circl(
                circl_data,
                CVE_ID
            )

            if circl_normalized is not None:

                print(
                    "[OK] CIRCL normalized"
                )

            else:

                print(
                    "[MISS] CIRCL normalized"
                )

        except Exception as error:

            print(
                f"[ERROR] CIRCL normalization failed: "
                f"{error}"
            )

    else:

        print(
            "[MISS] CIRCL normalized"
        )

    # =========================================================================
    # STEP 3
    # =========================================================================

    print()
    print("=" * 80)
    print(
        "STEP 3 - CONSOLIDATING INTO ONE DOCUMENT"
    )
    print("=" * 80)

    consolidated = consolidate_records(
        CVE_ID,
        osv_normalized,
        euvd_normalized,
        circl_normalized
    )

    print(
        json.dumps(
            consolidated,
            indent=2
        )
    )

    # =========================================================================
    # STEP 4
    # =========================================================================

    print()
    print("=" * 80)
    print(
        "STEP 4 - DATA SIZE COMPARISON"
    )
    print("=" * 80)

    combined_payload_bytes = (
        osv_bytes
        + euvd_bytes
        + circl_bytes
    )

    consolidated_bson_bytes = len(
        BSON.encode(
            consolidated
        )
    )

    if combined_payload_bytes > 0:

        reduction_percent = (
            1
            - (
                consolidated_bson_bytes
                / combined_payload_bytes
            )
        ) * 100

    else:

        reduction_percent = 0

    print(
        f"Combined API payloads : "
        f"{combined_payload_bytes:,} bytes"
    )

    print(
        f"Consolidated BSON     : "
        f"{consolidated_bson_bytes:,} bytes"
    )

    print(
        f"Payload reduction estimate: "
        f"{reduction_percent:.2f}%"
    )

    print()

    print(
        "Note: This is a payload-size estimate "
        "comparing JSON API response bytes with "
        "the consolidated BSON document size."
    )

    # =========================================================================
    # STEP 5
    # =========================================================================

    print()
    print("=" * 80)
    print(
        "STEP 5 - STORING ONE DOCUMENT IN MONGODB"
    )
    print("=" * 80)

    try:

        result = store_document(
            consolidated
        )

        print(
            "[OK] One consolidated document stored."
        )

        print(
            "[OK] Collection: "
            "vulnerability_intelligence"
        )

        print(
            f"[OK] Sources matched: "
            f"{consolidated['source_count']}/3"
        )

        if result.upserted_id is not None:

            print(
                f"[OK] MongoDB inserted new document: "
                f"{result.upserted_id}"
            )

        else:

            print(
                "[OK] Existing CVE document updated."
            )

    except Exception as error:

        print(
            f"[ERROR] MongoDB storage failed: "
            f"{error}"
        )

        return

    # =========================================================================
    # STORED DOCUMENT
    # =========================================================================

    print()
    print(
        "Stored MongoDB document:"
    )

    print(
        json.dumps(
            consolidated,
            indent=2
        )
    )

    # =========================================================================
    # FINAL STATUS
    # =========================================================================

    print()
    print("=" * 80)

    if (
        consolidated[
            "source_count"
        ] == 3
    ):

        print(
            "MULTI-SOURCE INTEGRATION COMPLETE - "
            "3/3 SOURCES MATCHED"
        )

    else:

        print(
            "MULTI-SOURCE INTEGRATION COMPLETE - "
            f"{consolidated['source_count']}/3 "
            "SOURCES MATCHED"
        )

    print("=" * 80)


# =============================================================================
# RUN
# =============================================================================

if __name__ == "__main__":
    main()