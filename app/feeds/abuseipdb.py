from collections.abc import Mapping
from typing import Any

import httpx

from app.feeds.base import FeedRecord
from app.models import ProviderName


class AbuseIPDBAdapter:
    provider = ProviderName.ABUSEIPDB

    def __init__(self, api_key: str, client: httpx.AsyncClient | None = None) -> None:
        self.api_key = api_key
        self.client = client or httpx.AsyncClient(timeout=30.0)
        self._owns_client = client is None

    async def fetch(self) -> list[FeedRecord]:
        response = await self.client.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Key": self.api_key, "Accept": "application/json"},
            params={"confidenceMinimum": 90, "limit": 100},
        )
        response.raise_for_status()
        return [record for item in response.json().get("data", []) if (record := self._item_to_record(item))]

    async def aclose(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    @staticmethod
    def _item_to_record(item: Mapping[str, Any]) -> FeedRecord | None:
        indicator = item.get("ipAddress")
        if not indicator:
            return None
        return {
            "indicator": indicator,
            "indicator_type": "ipv4",
            "confidence_score": item.get("abuseConfidenceScore", 0),
            "record_id": indicator,
            "source_url": f"https://www.abuseipdb.com/check/{indicator}",
            "last_seen": item.get("lastReportedAt"),
            "raw_metadata": {"country_code": item.get("countryCode"), "usage_type": item.get("usageType")},
        }
