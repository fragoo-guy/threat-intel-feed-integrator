import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from app.db.repository import IOCRepository
from app.models.ioc import IOC, IndicatorType, ProviderName, SourceEvidence, ThreatTag


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_repository_upsert_new_ioc_calls_insert() -> None:
    mock_db = MagicMock()
    mock_collection = MagicMock()
    mock_db.__getitem__.return_value = mock_collection

    mock_collection.find_one = AsyncMock(return_value=None)
    mock_collection.insert_one = AsyncMock()

    repo = IOCRepository(mock_db)
    ioc = IOC(
        indicator="198.51.100.5",
        indicator_type=IndicatorType.IPV4,
        deduplication_key="ipv4:198.51.100.5",
        confidence_score=70.0,
        sources=[SourceEvidence(provider=ProviderName.OTX)],
    )

    result = run(repo.upsert_ioc(ioc))

    assert result.indicator == "198.51.100.5"
    mock_collection.find_one.assert_called_once_with({"deduplication_key": "ipv4:198.51.100.5"})
    mock_collection.insert_one.assert_called_once()


def test_repository_upsert_existing_ioc_merges_and_replaces() -> None:
    mock_db = MagicMock()
    mock_collection = MagicMock()
    mock_db.__getitem__.return_value = mock_collection

    existing_doc = {
        "_id": "dummy_mongo_id",
        "indicator": "198.51.100.5",
        "indicator_type": "ipv4",
        "deduplication_key": "ipv4:198.51.100.5",
        "threat_tags": ["suspicious"],
        "confidence_score": 50.0,
        "sources": [{"provider": "otx", "confidence_score": 50.0, "metadata": {}}],
        "created_at": "2026-09-20T10:00:00Z",
        "updated_at": "2026-09-20T10:00:00Z",
        "raw_metadata": {},
    }

    mock_collection.find_one = AsyncMock(return_value=existing_doc)
    mock_collection.replace_one = AsyncMock()

    repo = IOCRepository(mock_db)
    incoming = IOC(
        indicator="198.51.100.5",
        indicator_type=IndicatorType.IPV4,
        deduplication_key="ipv4:198.51.100.5",
        threat_tags=[ThreatTag.MALWARE],
        confidence_score=80.0,
        sources=[SourceEvidence(provider=ProviderName.ABUSEIPDB, confidence_score=80.0)],
    )

    result = run(repo.upsert_ioc(incoming))

    # Verify merged attributes
    assert len(result.sources) == 2
    assert ThreatTag.SUSPICIOUS in result.threat_tags
    assert ThreatTag.MALWARE in result.threat_tags
    mock_collection.replace_one.assert_called_once()
    called_filter = mock_collection.replace_one.call_args[0][0]
    assert called_filter == {"deduplication_key": "ipv4:198.51.100.5"}


def test_repository_get_by_key_found() -> None:
    mock_db = MagicMock()
    mock_collection = MagicMock()
    mock_db.__getitem__.return_value = mock_collection

    doc = {
        "_id": "dummy_id",
        "indicator": "example.com",
        "indicator_type": "domain",
        "deduplication_key": "domain:example.com",
        "threat_tags": ["phishing"],
        "confidence_score": 60.0,
        "sources": [{"provider": "otx", "confidence_score": 60.0, "metadata": {}}],
        "created_at": "2026-09-20T10:00:00Z",
        "updated_at": "2026-09-20T10:00:00Z",
        "raw_metadata": {},
    }
    mock_collection.find_one = AsyncMock(return_value=doc)

    repo = IOCRepository(mock_db)
    result = run(repo.get_by_key("domain:example.com"))

    assert result is not None
    assert result.indicator == "example.com"
    assert result.threat_tags == [ThreatTag.PHISHING]
