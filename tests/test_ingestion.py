import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from app.feeds.base import FeedRecord
from app.models.ioc import IOC, IndicatorType, ProviderName, SourceEvidence, ThreatTag
from app.services.ingestion import FEED_HEALTH, IngestionService


def run(coro: Any) -> Any:
    return asyncio.run(coro)


class MockAdapter:
    provider = ProviderName.OTX

    def __init__(self, records: list[FeedRecord]) -> None:
        self._records = records

    async def fetch(self) -> list[FeedRecord]:
        return self._records


def test_ingestion_service_normalizes_enriches_and_upserts() -> None:
    records: list[FeedRecord] = [
        {
            "indicator": "203.0.113.10",
            "indicator_type": "ipv4",
            "confidence_score": 60,
            "threat_tags": ["suspicious"],
            "source_metadata": {"details": "Observed in Mirai botnet activity"},
            "raw_metadata": {"pulse_name": "Mirai wave"},
        }
    ]

    mock_repo = MagicMock()
    mock_repo.upsert_ioc = AsyncMock()

    service = IngestionService(mock_repo)
    adapter = MockAdapter(records)

    stats = run(service.ingest_feed(adapter))

    assert stats["status"] == "success"
    assert stats["records_fetched"] == 1
    assert stats["records_upserted"] == 1
    assert stats["errors"] == 0

    # Verify upsert was called with enriched tags
    mock_repo.upsert_ioc.assert_called_once()
    called_ioc: IOC = mock_repo.upsert_ioc.call_args[0][0]
    assert called_ioc.indicator == "203.0.113.10"
    assert ThreatTag.SUSPICIOUS in called_ioc.threat_tags
    assert ThreatTag.BOTNET in called_ioc.threat_tags  # Enriched from 'Mirai botnet' clue!


def test_ingestion_service_handles_adapter_failure_gracefully() -> None:
    class FailingAdapter:
        provider = ProviderName.ABUSEIPDB

        async def fetch(self) -> list[FeedRecord]:
            raise ConnectionError("AbuseIPDB API is currently unreachable")

    mock_repo = MagicMock()
    service = IngestionService(mock_repo)
    adapter = FailingAdapter()

    stats = run(service.ingest_feed(adapter))

    assert stats["status"] == "failed"
    assert "AbuseIPDB API is currently unreachable" in stats["error_message"]
    assert stats["records_fetched"] == 0
    assert FEED_HEALTH["abuseipdb"]["status"] == "failed"
