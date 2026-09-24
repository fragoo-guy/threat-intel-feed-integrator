from app.models.ioc import ThreatTag
from app.services.tagging import classify_text, enrich_threat_tags


def test_classify_text_matches_malware_keywords() -> None:
    tags = classify_text("Detected RedLine stealer and trojan payload")
    assert ThreatTag.MALWARE in tags


def test_classify_text_matches_c2_variations() -> None:
    tags = classify_text("Host is connecting to Cobalt Strike C2 beacon")
    assert ThreatTag.C2 in tags


def test_classify_text_matches_exploit_and_cve() -> None:
    tags = classify_text("Exploitation attempt for CVE-2024-1234 RCE vulnerability")
    assert ThreatTag.EXPLOIT in tags


def test_classify_text_matches_botnet_and_suspicious() -> None:
    tags = classify_text("Mirai botnet scanning on port 23 with bruteforce attempts")
    assert ThreatTag.BOTNET in tags
    assert ThreatTag.SUSPICIOUS in tags


def test_enrich_threat_tags_combines_and_deduplicates() -> None:
    existing = [ThreatTag.PHISHING]
    clues = ["Credential harvesting campaign", "Trojan dropper"]
    enriched = enrich_threat_tags(existing_tags=existing, text_clues=clues)

    assert ThreatTag.PHISHING in enriched
    assert ThreatTag.MALWARE in enriched
    # Ensure no duplicates
    assert len(enriched) == len(set(enriched))


def test_enrich_threat_tags_handles_string_tags() -> None:
    enriched = enrich_threat_tags(existing_tags=["c&c", "ransomware", "unknown-tag"])
    assert ThreatTag.C2 in enriched
    assert ThreatTag.MALWARE in enriched
