import re
from collections.abc import Iterable

from app.models.ioc import ThreatTag

_TAG_RULES: dict[ThreatTag, tuple[str, ...]] = {
    ThreatTag.MALWARE: (
        "malware",
        "trojan",
        "ransomware",
        "stealer",
        "keylogger",
        "worm",
        "virus",
        "dropper",
        "backdoor",
        "spyware",
        "miner",
        "cryptominer",
        "infostealer",
        "loader",
    ),
    ThreatTag.PHISHING: (
        "phish",
        "phishing",
        "spearphishing",
        "credential",
        "spoofing",
        "fake-login",
        "impersonation",
    ),
    ThreatTag.C2: (
        "c2",
        "c&c",
        "command-and-control",
        "command and control",
        "command_and_control",
        "beacon",
        "cobalt strike",
        "cobaltstrike",
        "meterpreter",
        "bot-master",
    ),
    ThreatTag.BOTNET: (
        "botnet",
        "mirai",
        "ddos",
        "qakbot",
        "emotet",
        "necurs",
        "zombie",
    ),
    ThreatTag.EXPLOIT: (
        "exploit",
        "cve-",
        "vulnerability",
        "rce",
        "zero-day",
        "0-day",
        "0day",
        "injection",
        "overflow",
    ),
    ThreatTag.SUSPICIOUS: (
        "suspicious",
        "scanner",
        "bruteforce",
        "brute-force",
        "reconnaissance",
        "portscan",
        "probe",
        "anomalous",
    ),
}

# Compile patterns for word-boundary or substring matches
_COMPILED_RULES: dict[ThreatTag, list[re.Pattern[str]]] = {
    tag: [re.compile(rf"(?:\b|_){re.escape(keyword)}(?:\b|_)", re.IGNORECASE) if " " not in keyword and "-" not in keyword
          else re.compile(re.escape(keyword), re.IGNORECASE)
          for keyword in keywords]
    for tag, keywords in _TAG_RULES.items()
}


def classify_text(text: str) -> list[ThreatTag]:
    """Inspect text (such as pulse descriptions, filenames, or raw tags) and extract matched ThreatTags."""
    if not text or not text.strip():
        return []

    matched: list[ThreatTag] = []
    for tag, patterns in _COMPILED_RULES.items():
        if any(pattern.search(text) for pattern in patterns):
            matched.append(tag)
    return matched


def enrich_threat_tags(
    existing_tags: Iterable[ThreatTag | str] | None = None,
    text_clues: Iterable[str] | None = None,
) -> list[ThreatTag]:
    """Combine existing tags with new classifications from contextual text clues, preserving uniqueness and order."""
    result: list[ThreatTag] = []

    # Include existing valid ThreatTags
    if existing_tags:
        for tag in existing_tags:
            if isinstance(tag, ThreatTag):
                if tag not in result:
                    result.append(tag)
            elif isinstance(tag, str):
                normalized = tag.strip().lower()
                try:
                    enum_tag = ThreatTag(normalized)
                    if enum_tag not in result:
                        result.append(enum_tag)
                except ValueError:
                    # Try text classification on the unknown string tag
                    for inferred in classify_text(normalized):
                        if inferred not in result:
                            result.append(inferred)

    # Classify contextual clues
    if text_clues:
        for clue in text_clues:
            for inferred in classify_text(clue):
                if inferred not in result:
                    result.append(inferred)

    return result
