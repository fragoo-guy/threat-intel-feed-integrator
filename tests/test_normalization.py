from datetime import timezone

from app.feeds.normalization import infer_indicator_type, normalize_record
from app.models import IndicatorType, ProviderName, ThreatTag


def test_infers_common_indicator_types() -> None:
    assert infer_indicator_type("203.0.113.5") is IndicatorType.IPV4
    assert infer_indicator_type("44d88612fea8a8f36de82e1278abb02f") is IndicatorType.MD5
    assert infer_indicator_type("https://example.com/path") is IndicatorType.URL
    assert infer_indicator_type("example.com") is IndicatorType.DOMAIN


def test_normalizes_provider_record_into_ioc() -> None:
    ioc = normalize_record(
        {
            "indicator": "Example.com",
            "confidence_score": 75,
            "threat_tags": ["phishing"],
            "record_id": "pulse-1",
            "first_seen": "2026-09-20T10:00:00Z",
            "last_seen": "2026-09-23T10:00:00Z",
        },
        ProviderName.OTX,
    )

    assert ioc.deduplication_key == "domain:example.com"
    assert ioc.threat_tags == [ThreatTag.PHISHING]
    assert ioc.sources[0].provider is ProviderName.OTX
    assert ioc.last_seen.tzinfo == timezone.utc


def test_normalizes_provider_type_aliases_and_ignores_unknown_tags() -> None:
    ioc = normalize_record(
        {
            "indicator": "44d88612fea8a8f36de82e1278abb02f",
            "indicator_type": "FileHash-MD5",
            "confidence_score": 60,
            "threat_tags": ["malware", "APT", "C&C"],
        },
        ProviderName.OTX,
    )

    assert ioc.indicator_type is IndicatorType.MD5
    assert ioc.threat_tags == [ThreatTag.MALWARE, ThreatTag.C2]


def test_normalizes_epoch_timestamps() -> None:
    ioc = normalize_record(
        {
            "indicator": "198.51.100.1",
            "indicator_type": "ipv4",
            "confidence_score": 80,
            "first_seen": 1711200000,
            "last_seen": 1711286400,
        },
        ProviderName.VIRUSTOTAL,
    )
    assert ioc.first_seen is not None
    assert ioc.first_seen.tzinfo == timezone.utc
    assert ioc.last_seen is not None
    assert ioc.last_seen.tzinfo == timezone.utc

