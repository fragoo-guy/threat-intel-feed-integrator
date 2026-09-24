from datetime import datetime, timezone

import pytest

from app.models.ioc import IOC, IndicatorType, ProviderName, SourceEvidence, ThreatTag
from app.services.deduplication import calculate_aggregate_confidence, merge_iocs


def test_calculate_aggregate_confidence_single_and_multi_source() -> None:
    # Single source
    s1 = SourceEvidence(provider=ProviderName.OTX, confidence_score=50.0)
    conf1 = calculate_aggregate_confidence([s1])
    assert conf1 == 50.0

    # Multi-source corroboration boost
    s2 = SourceEvidence(provider=ProviderName.ABUSEIPDB, confidence_score=80.0)
    conf2 = calculate_aggregate_confidence([s1, s2])
    # Base: (80 * 0.7) + (65 * 0.3) = 56 + 19.5 = 75.5. Boost: +10 = 85.5
    assert conf2 == 85.5


def test_merge_iocs_combines_sources_and_tags() -> None:
    dt1 = datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc)
    dt2 = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
    dt3 = datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc)

    ioc1 = IOC(
        indicator="198.51.100.25",
        indicator_type=IndicatorType.IPV4,
        deduplication_key="ipv4:198.51.100.25",
        threat_tags=[ThreatTag.SUSPICIOUS],
        confidence_score=40.0,
        sources=[
            SourceEvidence(
                provider=ProviderName.OTX,
                confidence_score=40.0,
                first_seen=dt1,
                last_seen=dt2,
                metadata={"pulse": "P1"},
            )
        ],
        first_seen=dt1,
        last_seen=dt2,
    )

    ioc2 = IOC(
        indicator="198.51.100.25",
        indicator_type=IndicatorType.IPV4,
        deduplication_key="ipv4:198.51.100.25",
        threat_tags=[ThreatTag.MALWARE, ThreatTag.SUSPICIOUS],
        confidence_score=75.0,
        sources=[
            SourceEvidence(
                provider=ProviderName.ABUSEIPDB,
                confidence_score=75.0,
                first_seen=dt2,
                last_seen=dt3,
                metadata={"reports": 15},
            )
        ],
        first_seen=dt2,
        last_seen=dt3,
    )

    merged = merge_iocs(ioc1, ioc2)

    # Indicator and key preserved
    assert merged.indicator == "198.51.100.25"
    assert merged.deduplication_key == "ipv4:198.51.100.25"

    # Both sources retained
    assert len(merged.sources) == 2
    providers = {s.provider for s in merged.sources}
    assert providers == {ProviderName.OTX, ProviderName.ABUSEIPDB}

    # Threat tags merged without duplicates
    assert set(merged.threat_tags) == {ThreatTag.SUSPICIOUS, ThreatTag.MALWARE}
    assert len(merged.threat_tags) == 2

    # Timestamps bounded to earliest and latest
    assert merged.first_seen == dt1
    assert merged.last_seen == dt3

    # Multi-source confidence boosted above individual scores
    assert merged.confidence_score > 75.0


def test_merge_iocs_mismatched_key_raises_error() -> None:
    ioc1 = IOC(
        indicator="198.51.100.1",
        indicator_type=IndicatorType.IPV4,
        deduplication_key="ipv4:198.51.100.1",
        confidence_score=50.0,
        sources=[SourceEvidence(provider=ProviderName.OTX)],
    )
    ioc2 = IOC(
        indicator="198.51.100.2",
        indicator_type=IndicatorType.IPV4,
        deduplication_key="ipv4:198.51.100.2",
        confidence_score=50.0,
        sources=[SourceEvidence(provider=ProviderName.ABUSEIPDB)],
    )

    with pytest.raises(ValueError, match="Cannot merge mismatched IOCs"):
        merge_iocs(ioc1, ioc2)
