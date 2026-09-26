from collections.abc import Sequence
from datetime import datetime, timezone
import json
from typing import Any
import uuid

import stix2

from app.models.ioc import IOC, IndicatorType


def _build_stix_pattern(indicator_type: IndicatorType, indicator: str) -> str:
    """Build a standard STIX 2.1 comparison expression pattern."""
    # Escape single quotes in observable indicator values
    clean_val = indicator.replace("\\", "\\\\").replace("'", "\\'")
    if indicator_type == IndicatorType.IPV4:
        return f"[ipv4-addr:value = '{clean_val}']"
    elif indicator_type == IndicatorType.IPV6:
        return f"[ipv6-addr:value = '{clean_val}']"
    elif indicator_type == IndicatorType.DOMAIN:
        return f"[domain-name:value = '{clean_val}']"
    elif indicator_type == IndicatorType.URL:
        return f"[url:value = '{clean_val}']"
    elif indicator_type == IndicatorType.EMAIL:
        return f"[email-addr:value = '{clean_val}']"
    elif indicator_type == IndicatorType.MD5:
        return f"[file:hashes.'MD5' = '{clean_val}']"
    elif indicator_type == IndicatorType.SHA1:
        return f"[file:hashes.'SHA-1' = '{clean_val}']"
    elif indicator_type == IndicatorType.SHA256:
        return f"[file:hashes.'SHA-256' = '{clean_val}']"
    elif indicator_type == IndicatorType.FILE_NAME:
        return f"[file:name = '{clean_val}']"
    return f"[artifact:payload_bin = '{clean_val}']"


def export_iocs_to_stix(iocs: Sequence[IOC]) -> dict[str, Any]:
    """Serialize a sequence of IOCs into a compliant STIX 2.1 Bundle dictionary."""
    stix_objects: list[Any] = []

    for ioc in iocs:
        pattern = _build_stix_pattern(ioc.indicator_type, ioc.indicator)
        valid_from = ioc.first_seen or ioc.created_at
        if valid_from.tzinfo is None:
            valid_from = valid_from.replace(tzinfo=timezone.utc)

        labels = [tag.value for tag in ioc.threat_tags]
        if not labels:
            labels = ["malicious-activity"]

        sources_summary = ", ".join(sorted({s.provider.value for s in ioc.sources}))
        description = f"Threat indicator aggregated from {len(ioc.sources)} source(s): {sources_summary}"

        try:
            indicator_obj = stix2.Indicator(
                spec_version="2.1",
                name=f"{ioc.indicator_type.value.upper()}: {ioc.indicator}",
                pattern_type="stix",
                pattern=pattern,
                valid_from=valid_from,
                confidence=int(round(ioc.confidence_score)),
                labels=labels,
                description=description,
                allow_custom=True,
            )
            stix_objects.append(indicator_obj)
        except Exception:
            # Fallback manual STIX 2.1 indicator dict if library validation fails
            indicator_id = f"indicator--{uuid.uuid4()}"
            stix_objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created": ioc.created_at.isoformat(),
                    "modified": ioc.updated_at.isoformat(),
                    "name": f"{ioc.indicator_type.value.upper()}: {ioc.indicator}",
                    "description": description,
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": valid_from.isoformat(),
                    "confidence": int(round(ioc.confidence_score)),
                    "labels": labels,
                }
            )

    try:
        bundle = stix2.Bundle(objects=stix_objects, allow_custom=True)
        return json.loads(bundle.serialize())
    except Exception:
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [obj.to_dict() if hasattr(obj, "to_dict") else obj for obj in stix_objects],
        }
