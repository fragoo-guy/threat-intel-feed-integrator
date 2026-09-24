from collections.abc import Mapping
from datetime import datetime, timezone
from ipaddress import ip_address
from urllib.parse import urlparse

from app.models import IOC, IndicatorType, ProviderName, SourceEvidence, ThreatTag


_INDICATOR_TYPE_ALIASES = {
    "ipv4": IndicatorType.IPV4,
    "ipv6": IndicatorType.IPV6,
    "domain": IndicatorType.DOMAIN,
    "hostname": IndicatorType.DOMAIN,
    "url": IndicatorType.URL,
    "email": IndicatorType.EMAIL,
    "filehash-md5": IndicatorType.MD5,
    "md5": IndicatorType.MD5,
    "filehash-sha1": IndicatorType.SHA1,
    "sha1": IndicatorType.SHA1,
    "filehash-sha256": IndicatorType.SHA256,
    "sha256": IndicatorType.SHA256,
    "filename": IndicatorType.FILE_NAME,
    "file_name": IndicatorType.FILE_NAME,
}


def infer_indicator_type(indicator: str) -> IndicatorType:
    try:
        address = ip_address(indicator)
    except ValueError:
        address = None
    if address:
        return IndicatorType.IPV4 if address.version == 4 else IndicatorType.IPV6

    lowered = indicator.lower()
    if len(lowered) == 32 and _is_hex(lowered):
        return IndicatorType.MD5
    if len(lowered) == 40 and _is_hex(lowered):
        return IndicatorType.SHA1
    if len(lowered) == 64 and _is_hex(lowered):
        return IndicatorType.SHA256
    if "@" in indicator and " " not in indicator:
        return IndicatorType.EMAIL
    if urlparse(indicator).scheme in {"http", "https"}:
        return IndicatorType.URL
    if "." in indicator and " " not in indicator and "/" not in indicator:
        return IndicatorType.DOMAIN
    return IndicatorType.FILE_NAME


def normalize_record(record: Mapping[str, object], provider: ProviderName) -> IOC:
    indicator = _required_string(record, "indicator")
    indicator_type = _parse_indicator_type(record.get("indicator_type"), indicator)
    source = SourceEvidence(
        provider=provider,
        record_id=_optional_string(record.get("record_id")),
        source_url=_optional_string(record.get("source_url")),
        confidence_score=_optional_float(record.get("confidence_score")),
        first_seen=_optional_datetime(record.get("first_seen")),
        last_seen=_optional_datetime(record.get("last_seen")),
        metadata=dict(record.get("source_metadata", {})),
    )
    tags = _normalize_tags(record.get("threat_tags", []))
    canonical_indicator = indicator.strip()
    return IOC(
        indicator=canonical_indicator,
        indicator_type=indicator_type,
        deduplication_key=f"{indicator_type.value}:{canonical_indicator.lower()}",
        threat_tags=tags,
        confidence_score=_required_float(record, "confidence_score", default=0),
        sources=[source],
        first_seen=source.first_seen,
        last_seen=source.last_seen,
        raw_metadata=dict(record.get("raw_metadata", {})),
    )


def _is_hex(value: str) -> bool:
    return all(character in "0123456789abcdef" for character in value)


def _parse_indicator_type(value: object, indicator: str) -> IndicatorType:
    if not value:
        return infer_indicator_type(indicator)
    if not isinstance(value, str):
        raise ValueError("indicator_type must be a string")
    try:
        return _INDICATOR_TYPE_ALIASES[value.strip().lower()]
    except KeyError as error:
        raise ValueError(f"unsupported provider indicator type: {value}") from error


def _normalize_tags(values: object) -> list[ThreatTag]:
    if not isinstance(values, list | tuple | set):
        return []
    aliases = {
        "c&c": ThreatTag.C2,
        "command-and-control": ThreatTag.C2,
        "command_and_control": ThreatTag.C2,
    }
    tags: list[ThreatTag] = []
    for value in values:
        if not isinstance(value, str):
            continue
        normalized = value.strip().lower()
        try:
            tag = aliases[normalized] if normalized in aliases else ThreatTag(normalized)
        except ValueError:
            continue
        if tag not in tags:
            tags.append(tag)
    return tags


def _required_string(record: Mapping[str, object], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"feed record requires a non-empty {key}")
    return value


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _optional_float(value: object) -> float | None:
    if value is None:
        return None
    return float(value)


def _required_float(record: Mapping[str, object], key: str, default: float) -> float:
    value = record.get(key, default)
    return float(value)


def _optional_datetime(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            numeric_val = float(value)
            return datetime.fromtimestamp(numeric_val, tz=timezone.utc)
        except ValueError:
            pass
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    raise ValueError("feed timestamps must be datetime values, Unix epoch numbers, or ISO-8601 strings")
