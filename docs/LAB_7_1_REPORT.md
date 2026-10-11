# LAB 7.1 – ANALYZE A PRODUCTION SCHEMA

## SENTINEL CTI – Cyber Threat Intelligence Monitoring and Analysis Platform

---

## 1. Objective

The objective of this lab is to examine a realistic Cyber Threat Intelligence (CTI) MongoDB schema and identify which relationships are implemented using embedding and which are implemented using referencing.

The lab also evaluates BSON document sizes using MongoDB's `$bsonSize` expression, verifies that documents remain below the 16 MiB BSON document limit, and experiments with redesigning a referencing relationship as an embedded relationship.

---

## 2. CTI Production-Style Schema

The SENTINEL CTI platform models information using the following collections:

- `sources`
- `threats`
- `iocs`
- `reports`

A report can be associated with a source, threat, and multiple Indicators of Compromise (IOCs).

Small report-specific information such as tags, classification, and observations is stored inside the report document.

---

## 3. Embedding and Referencing Decisions

| Relationship | Design | Reason |
|---|---|---|
| Report → Source | REFERENCE | Source information can be shared and maintained independently |
| Report → Threat | REFERENCE | A threat can appear in multiple reports and has its own lifecycle |
| Report → IOC | REFERENCE | IOCs can occur in multiple reports and can be independently searched, updated, and reused |
| Report → Tags | EMBED | Tags are small bounded values that are normally read together with the report |
| Report → Classification | EMBED | Classification belongs directly to the report |
| Report → Observations | EMBED | Observations are small and report-specific |

---

## 4. Why Referencing Is Used

### 4.1 Report → Source

A source is referenced instead of embedded because source information may be shared by multiple reports.

Embedding the complete source object inside every report would repeat the same information.

### 4.2 Report → Threat

Threat information is referenced because a single threat can appear in multiple reports.

The threat can also have an independent lifecycle and can be updated separately from individual reports.

### 4.3 Report → IOC

IOCs are referenced because the same indicator can occur in multiple reports.

An IOC may also need to be searched, updated, or reused independently.

---

## 5. Embedded Alternatives

If the referenced relationships were embedded, the report document could contain the related information directly.

For example, an embedded threat could look conceptually like:

```json
{
  "report_id": "RPT-001",
  "title": "Ransomware Activity Intelligence Brief",
  "threat": {
    "threat_id": "THR-001",
    "name": "DemoRansom",
    "category": "Ransomware",
    "severity": "Critical"
  }
}