# LAB 7.2 – WORKING SET ANALYSIS

## SENTINEL CTI – Cyber Threat Intelligence Monitoring and Analysis Platform

---

## 1. Objective

The objective of this lab is to estimate the working set of a MongoDB collection and evaluate whether the working set can fit within the WiredTiger cache.

The experiment creates 100,000 documents of approximately 2 KB each, performs random reads across the collection, observes WiredTiger cache statistics using `serverStatus`, and monitors a public security-report source every 10 seconds.

---

## 2. Dataset and Working Set

The experiment creates a collection containing:

```text
Number of documents : 100,000
Target document size: approximately 2 KB