from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.models import IOC, IndicatorType, ProviderName, SourceEvidence, ThreatTag


def make_source() -> SourceEvidence:
    return SourceEvidence(
        provider=ProviderName.OTX,
        record_id="pulse-123",
        confidence_score=80,
    )


def test_ioc_normalizes_indicator_and_deduplication_key() -> None:
    ioc = IOC(
        indicator="  Example.COM ",
        indicator_type=IndicatorType.DOMAIN,
        deduplication_key="DOMAIN:example.com",
        threat_tags=[ThreatTag.PHISHING],
        confidence_score=80,
        sources=[make_source()],
    )

    assert ioc.indicator == "Example.COM"
    assert ioc.deduplication_key == "domain:example.com"
    assert ioc.created_at.tzinfo == timezone.utc


def test_ioc_rejects_mismatched_deduplication_key() -> None:
    with pytest.raises(ValidationError, match="deduplication_key"):
        IOC(
            indicator="203.0.113.10",
            indicator_type=IndicatorType.IPV4,
            deduplication_key="domain:203.0.113.10",
            threat_tags=[],
            confidence_score=50,
            sources=[make_source()],
        )


def test_ioc_rejects_invalid_confidence_and_time_order() -> None:
    with pytest.raises(ValidationError):
        IOC(
            indicator="203.0.113.10",
            indicator_type=IndicatorType.IPV4,
            deduplication_key="ipv4:203.0.113.10",
            confidence_score=101,
            sources=[
                SourceEvidence(
                    provider=ProviderName.ABUSEIPDB,
                    first_seen=datetime(2026, 9, 23, tzinfo=timezone.utc),
                    last_seen=datetime(2026, 9, 22, tzinfo=timezone.utc),
                )
            ],
        )
