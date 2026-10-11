import json
from pathlib import Path


OUTPUT_FILE = Path(__file__).resolve().parent / "cti_7_1_seed.json"


sources = [
    {
        "source_id": "SRC-001",
        "name": "CTI Digest",
        "source_type": "CTI Aggregator",
        "url": "https://ctidigest.com/",
        "record_origin": "source_structure_reference",
    },
    {
        "source_id": "SRC-002",
        "name": "Open Source Threat Research",
        "source_type": "Research Feed",
        "url": None,
        "record_origin": "synthetic_demo",
    },
    {
        "source_id": "SRC-003",
        "name": "Security Vendor Intelligence",
        "source_type": "Vendor Feed",
        "url": None,
        "record_origin": "synthetic_demo",
    },
    {
        "source_id": "SRC-004",
        "name": "Government Cyber Advisory",
        "source_type": "Advisory Feed",
        "url": None,
        "record_origin": "synthetic_demo",
    },
]


threats = [
    {
        "threat_id": "THR-001",
        "name": "DemoRansom",
        "type": "Ransomware",
        "severity": "Critical",
        "aliases": ["DemoRansom"],
        "record_origin": "synthetic_demo",
    },
    {
        "threat_id": "THR-002",
        "name": "DemoStealer",
        "type": "Infostealer",
        "severity": "High",
        "aliases": ["DemoStealer", "InfoDemo"],
        "record_origin": "synthetic_demo",
    },
    {
        "threat_id": "THR-003",
        "name": "DemoPhish",
        "type": "Phishing",
        "severity": "High",
        "aliases": ["DemoPhish"],
        "record_origin": "synthetic_demo",
    },
    {
        "threat_id": "THR-004",
        "name": "DemoBot",
        "type": "Botnet",
        "severity": "High",
        "aliases": ["DemoBot"],
        "record_origin": "synthetic_demo",
    },
    {
        "threat_id": "THR-005",
        "name": "DemoExploit",
        "type": "Vulnerability",
        "severity": "Critical",
        "aliases": ["DemoExploit"],
        "record_origin": "synthetic_demo",
    },
]


iocs = [
    {
        "ioc_id": "IOC-001",
        "indicator": "192.0.2.10",
        "type": "IP",
        "confidence": 94,
        "category": "Ransomware",
        "first_seen": "2026-01-12",
        "record_origin": "synthetic_demo",
    },
    {
        "ioc_id": "IOC-002",
        "indicator": "198.51.100.24",
        "type": "IP",
        "confidence": 88,
        "category": "Ransomware",
        "first_seen": "2026-01-14",
        "record_origin": "synthetic_demo",
    },
    {
        "ioc_id": "IOC-003",
        "indicator": "example-malware.com",
        "type": "Domain",
        "confidence": 91,
        "category": "Infostealer",
        "first_seen": "2026-01-18",
        "record_origin": "synthetic_demo",
    },
    {
        "ioc_id": "IOC-004",
        "indicator": "example-login.net",
        "type": "Domain",
        "confidence": 86,
        "category": "Phishing",
        "first_seen": "2026-01-21",
        "record_origin": "synthetic_demo",
    },
    {
        "ioc_id": "IOC-005",
        "indicator": "203.0.113.45",
        "type": "IP",
        "confidence": 89,
        "category": "Botnet",
        "first_seen": "2026-01-25",
        "record_origin": "synthetic_demo",
    },
    {
        "ioc_id": "IOC-006",
        "indicator": "https://example.org/update",
        "type": "URL",
        "confidence": 84,
        "category": "Infostealer",
        "first_seen": "2026-01-29",
        "record_origin": "synthetic_demo",
    },
    {
        "ioc_id": "IOC-007",
        "indicator": "https://example.net/verify",
        "type": "URL",
        "confidence": 82,
        "category": "Phishing",
        "first_seen": "2026-02-02",
        "record_origin": "synthetic_demo",
    },
    {
        "ioc_id": "IOC-008",
        "indicator": (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        "type": "Hash",
        "confidence": 97,
        "category": "Malware",
        "first_seen": "2026-02-04",
        "record_origin": "synthetic_demo",
    },
    {
        "ioc_id": "IOC-009",
        "indicator": (
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ),
        "type": "Hash",
        "confidence": 93,
        "category": "Ransomware",
        "first_seen": "2026-02-07",
        "record_origin": "synthetic_demo",
    },
    {
        "ioc_id": "IOC-010",
        "indicator": "192.0.2.88",
        "type": "IP",
        "confidence": 79,
        "category": "Botnet",
        "first_seen": "2026-02-11",
        "record_origin": "synthetic_demo",
    },
    {
        "ioc_id": "IOC-011",
        "indicator": "example-c2.org",
        "type": "Domain",
        "confidence": 90,
        "category": "Malware",
        "first_seen": "2026-02-14",
        "record_origin": "synthetic_demo",
    },
    {
        "ioc_id": "IOC-012",
        "indicator": "https://example.com/download",
        "type": "URL",
        "confidence": 87,
        "category": "Malware",
        "first_seen": "2026-02-18",
        "record_origin": "synthetic_demo",
    },
]


reports = [
    {
        "report_id": "RPT-001",
        "title": "Ransomware Activity Intelligence Brief",
        "source_id": "SRC-001",
        "published_date": "2026-02-20",
        "year": 2026,
        "category": "Ransomware",
        "report_type": "Analysis",
        "summary": (
            "Synthetic CTI report used to demonstrate ransomware "
            "intelligence schema design."
        ),
        "tags": ["ransomware", "extortion", "incident-response"],
        "classification": {
            "label": "Ransomware",
            "confidence": 0.94,
            "method": "rule_based_demo",
        },
        "observations": [
            {"label": "Encrypted files", "importance": "high"},
            {"label": "Extortion behaviour", "importance": "high"},
        ],
        "threat_ids": ["THR-001"],
        "ioc_ids": ["IOC-001", "IOC-002", "IOC-009"],
        "record_origin": "synthetic_demo",
    },
    {
        "report_id": "RPT-002",
        "title": "Information Stealer Intelligence Brief",
        "source_id": "SRC-002",
        "published_date": "2026-02-22",
        "year": 2026,
        "category": "Malware",
        "report_type": "Analysis",
        "summary": (
            "Synthetic report demonstrating an infostealer-related "
            "CTI record."
        ),
        "tags": ["infostealer", "credentials", "malware"],
        "classification": {
            "label": "Infostealer",
            "confidence": 0.91,
            "method": "rule_based_demo",
        },
        "observations": [
            {"label": "Credential theft", "importance": "high"},
            {"label": "Malicious download", "importance": "medium"},
        ],
        "threat_ids": ["THR-002"],
        "ioc_ids": ["IOC-003", "IOC-006", "IOC-008"],
        "record_origin": "synthetic_demo",
    },
    {
        "report_id": "RPT-003",
        "title": "Phishing Campaign Intelligence Brief",
        "source_id": "SRC-003",
        "published_date": "2026-02-24",
        "year": 2026,
        "category": "Phishing",
        "report_type": "Analysis",
        "summary": (
            "Synthetic report demonstrating phishing-related "
            "CTI records."
        ),
        "tags": ["phishing", "credential-harvesting", "social-engineering"],
        "classification": {
            "label": "Phishing",
            "confidence": 0.89,
            "method": "rule_based_demo",
        },
        "observations": [
            {"label": "Credential harvesting", "importance": "high"},
            {"label": "Suspicious login page", "importance": "medium"},
        ],
        "threat_ids": ["THR-003"],
        "ioc_ids": ["IOC-004", "IOC-007"],
        "record_origin": "synthetic_demo",
    },
    {
        "report_id": "RPT-004",
        "title": "Botnet Infrastructure Intelligence Brief",
        "source_id": "SRC-004",
        "published_date": "2026-02-26",
        "year": 2026,
        "category": "Botnet",
        "report_type": "Analysis",
        "summary": (
            "Synthetic report demonstrating botnet-related "
            "infrastructure intelligence."
        ),
        "tags": ["botnet", "command-and-control", "infrastructure"],
        "classification": {
            "label": "Botnet",
            "confidence": 0.87,
            "method": "rule_based_demo",
        },
        "observations": [
            {"label": "Command-and-control activity", "importance": "high"},
            {"label": "Repeated outbound connections", "importance": "medium"},
        ],
        "threat_ids": ["THR-004"],
        "ioc_ids": ["IOC-005", "IOC-010", "IOC-011"],
        "record_origin": "synthetic_demo",
    },
    {
        "report_id": "RPT-005",
        "title": "Vulnerability Exploitation Intelligence Brief",
        "source_id": "SRC-001",
        "published_date": "2026-03-01",
        "year": 2026,
        "category": "Vulnerability",
        "report_type": "Analysis",
        "summary": (
            "Synthetic report demonstrating a vulnerability-focused "
            "threat record."
        ),
        "tags": ["vulnerability", "exploitation", "patching"],
        "classification": {
            "label": "Vulnerability",
            "confidence": 0.92,
            "method": "rule_based_demo",
        },
        "observations": [
            {"label": "Publicly exposed service", "importance": "high"},
            {"label": "Exploit attempt", "importance": "high"},
        ],
        "threat_ids": ["THR-005"],
        "ioc_ids": ["IOC-011", "IOC-012"],
        "record_origin": "synthetic_demo",
    },
    {
        "report_id": "RPT-006",
        "title": "Combined Malware and Ransomware Intelligence Brief",
        "source_id": "SRC-002",
        "published_date": "2026-03-05",
        "year": 2026,
        "category": "Malware",
        "report_type": "Analysis",
        "summary": (
            "Synthetic multi-threat report used to demonstrate "
            "many-to-many references."
        ),
        "tags": ["malware", "ransomware", "threat-correlation"],
        "classification": {
            "label": "Malware",
            "confidence": 0.88,
            "method": "rule_based_demo",
        },
        "observations": [
            {"label": "Malware delivery", "importance": "high"},
            {"label": "Ransomware follow-on activity", "importance": "high"},
        ],
        "threat_ids": ["THR-001", "THR-002"],
        "ioc_ids": ["IOC-002", "IOC-006", "IOC-008", "IOC-009"],
        "record_origin": "synthetic_demo",
    },
]


dataset = {
    "sources": sources,
    "threats": threats,
    "iocs": iocs,
    "reports": reports,
}


with OUTPUT_FILE.open("w", encoding="utf-8") as file:
    json.dump(dataset, file, indent=2, ensure_ascii=False)

print(f"[OK] Created: {OUTPUT_FILE}")
print(f"Sources : {len(sources)}")
print(f"Threats : {len(threats)}")
print(f"IOCs    : {len(iocs)}")
print(f"Reports : {len(reports)}")