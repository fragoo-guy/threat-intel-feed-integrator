from typing import Any

MITRE_MAPPINGS: dict[str, dict[str, str]] = {
    "malware": {
        "technique_id": "T1204",
        "technique_name": "User Execution: Malicious Payload",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1204/",
    },
    "phishing": {
        "technique_id": "T1566",
        "technique_name": "Phishing: Spearphishing Link / Attachment",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/",
    },
    "c2": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol: C2 Communication",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
    "botnet": {
        "technique_id": "T1584",
        "technique_name": "Compromise Infrastructure: Botnet",
        "tactic": "Resource Development",
        "url": "https://attack.mitre.org/techniques/T1584/",
    },
    "exploit": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "suspicious": {
        "technique_id": "T1583",
        "technique_name": "Acquire Infrastructure: Domains / Virtual Private Servers",
        "tactic": "Resource Development",
        "url": "https://attack.mitre.org/techniques/T1583/",
    },
}


def get_mitre_context(tags: list[str]) -> list[dict[str, str]]:
    """Return mapped MITRE ATT&CK techniques for a given set of threat tags."""
    results: list[dict[str, str]] = []
    seen: set[str] = set()
    for tag in tags:
        clean_tag = tag.strip().lower()
        if clean_tag in MITRE_MAPPINGS and clean_tag not in seen:
            results.append(MITRE_MAPPINGS[clean_tag])
            seen.add(clean_tag)
    return results


def generate_suricata_rule(ioc: dict[str, Any], sid_base: int = 1000001) -> str:
    """Generate a valid Suricata / Snort NIDS rule for the given indicator."""
    ind = ioc.get("indicator", "unknown")
    itype = ioc.get("indicator_type", "unknown")
    tags = ", ".join(ioc.get("threat_tags", ["threat"]))
    conf = ioc.get("confidence_score", 0)

    if itype in ("ipv4", "ipv6"):
        return (
            f'alert ip any any -> [{ind}] any '
            f'(msg:"[THREAT-INTEL] High-Confidence Malicious IP ({tags}) - Score {conf}%"; '
            f'reference:url,https://github.com/fragoo-guy/threat-intel-feed-integrator; '
            f'classtype:trojan-activity; sid:{sid_base}; rev:1;)'
        )
    elif itype == "domain":
        return (
            f'alert dns any any -> any any '
            f'(msg:"[THREAT-INTEL] Malicious Domain Lookup: {ind} ({tags})"; '
            f'dns.query; content:"{ind}"; nocase; '
            f'reference:url,https://github.com/fragoo-guy/threat-intel-feed-integrator; '
            f'classtype:bad-unknown; sid:{sid_base}; rev:1;)'
        )
    elif itype == "url":
        return (
            f'alert http any any -> any any '
            f'(msg:"[THREAT-INTEL] Suspicious HTTP Request ({tags})"; '
            f'http.uri; content:"{ind}"; nocase; '
            f'reference:url,https://github.com/fragoo-guy/threat-intel-feed-integrator; '
            f'classtype:web-application-attack; sid:{sid_base}; rev:1;)'
        )
    else:
        return f"# Suricata network rule not directly applicable for file hash or name: {ind}"
