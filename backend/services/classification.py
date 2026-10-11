"""
SENTINEL CTI
Explainable rule-based threat classification engine.

This classifier is designed for demonstration and academic use.
It does not call an external AI/API service.
"""

import re


# Rule definitions
CLASSIFICATION_RULES = {
    "Ransomware": {
        "keywords": [
            "ransomware",
            "ransom",
            "encrypted files",
            "file encryption",
            "extortion",
            "double extortion",
            "triple extortion",
            "ransom demand",
            "lock files"
        ],
        "severity": "Critical"
    },

    "Infostealer": {
        "keywords": [
            "infostealer",
            "information stealer",
            "credential theft",
            "stolen credentials",
            "password theft",
            "browser credentials",
            "cookie theft",
            "credential stealing"
        ],
        "severity": "High"
    },

    "Phishing": {
        "keywords": [
            "phishing",
            "credential harvesting",
            "fake login",
            "malicious email",
            "spear phishing",
            "social engineering",
            "login page",
            "credential harvesting"
        ],
        "severity": "High"
    },

    "Botnet": {
        "keywords": [
            "botnet",
            "command and control",
            "c2",
            "c&c",
            "distributed denial",
            "ddos",
            "infected devices",
            "automated attacks"
        ],
        "severity": "High"
    },

    "Vulnerability": {
        "keywords": [
            "vulnerability",
            "zero-day",
            "zero day",
            "cve-",
            "security flaw",
            "remote code execution",
            "privilege escalation",
            "exploit"
        ],
        "severity": "Critical"
    },

    "Malware": {
        "keywords": [
            "malware",
            "trojan",
            "rat",
            "remote access trojan",
            "malicious payload",
            "malicious software"
        ],
        "severity": "High"
    }
}


def normalize_text(text):
    """Normalize input text for matching."""

    if not text:
        return ""

    return re.sub(
        r"\s+",
        " ",
        str(text).lower().strip()
    )


def classify_threat(text="", ioc_type=None):
    """
    Classify a threat using transparent keyword rules.

    Returns:
        category
        severity
        score
        matched_keywords
        explanation
    """

    normalized_text = normalize_text(text)

    scores = {}
    matches = {}

    for category, rule in CLASSIFICATION_RULES.items():

        matched = []

        for keyword in rule["keywords"]:
            if keyword in normalized_text:
                matched.append(keyword)

        scores[category] = len(matched)
        matches[category] = matched

    # IOC type can provide additional context
    if ioc_type:
        normalized_type = normalize_text(ioc_type)

        if normalized_type == "hash":
            scores["Malware"] += 1
            matches["Malware"].append("IOC type: Hash")

        elif normalized_type == "url":
            scores["Phishing"] += 1
            matches["Phishing"].append("IOC type: URL")

        elif normalized_type == "domain":
            scores["Phishing"] += 1
            matches["Phishing"].append("IOC type: Domain")

        elif normalized_type == "ip":
            scores["Botnet"] += 1
            matches["Botnet"].append("IOC type: IP")

    # Determine highest-scoring classification
    best_category = max(
        scores,
        key=scores.get
    )

    best_score = scores[best_category]

    # No evidence found
    if best_score == 0:
        return {
            "category": "Unknown",
            "severity": "Unclassified",
            "score": 0,
            "matched_keywords": [],
            "explanation": (
                "No classification rule matched the supplied input."
            )
        }

    matched_keywords = matches[best_category]

    severity = CLASSIFICATION_RULES[best_category]["severity"]

    explanation = (
        f"Classified as {best_category} because the input "
        f"matched: {', '.join(matched_keywords)}."
    )

    return {
        "category": best_category,
        "severity": severity,
        "score": best_score,
        "matched_keywords": matched_keywords,
        "explanation": explanation
    }