from services.classification import classify_threat


print("=" * 60)
print("SENTINEL CTI — THREAT CLASSIFICATION TEST")
print("=" * 60)


test_cases = [
    {
        "text": "The attacker encrypted files and demanded a ransom payment.",
        "ioc_type": None
    },
    {
        "text": "The campaign targeted users with fake login pages to steal credentials.",
        "ioc_type": "URL"
    },
    {
        "text": "The malware steals browser passwords and stored credentials.",
        "ioc_type": None
    },
    {
        "text": "A large botnet was used to launch a distributed denial of service attack.",
        "ioc_type": "IP"
    },
    {
        "text": "The attacker exploited a critical zero-day vulnerability.",
        "ioc_type": None
    },
    {
        "text": "Unknown activity detected.",
        "ioc_type": None
    }
]


for number, case in enumerate(test_cases, start=1):

    result = classify_threat(
        text=case["text"],
        ioc_type=case["ioc_type"]
    )

    print(f"\nTest {number}")
    print("-" * 40)
    print(f"Input       : {case['text']}")
    print(f"IOC Type    : {case['ioc_type']}")
    print(f"Category    : {result['category']}")
    print(f"Severity    : {result['severity']}")
    print(f"Score       : {result['score']}")
    print(f"Matched     : {result['matched_keywords']}")
    print(f"Explanation : {result['explanation']}")


print("\n" + "=" * 60)
print("CLASSIFICATION TEST COMPLETED")
print("=" * 60)