from collections.abc import Mapping
from typing import Any

import httpx

from app.feeds.base import FeedRecord
from app.models import ProviderName


class VirusTotalAdapter:
    provider = ProviderName.VIRUSTOTAL

    def __init__(self, api_key: str, query: str = "type:file", client: httpx.AsyncClient | None = None) -> None:
        self.api_key = api_key
        self.query = query
        self.client = client or httpx.AsyncClient(timeout=30.0)
        self._owns_client = client is None

    async def fetch(self) -> list[FeedRecord]:
        response = await self.client.get(
            "https://www.virustotal.com/api/v3/intelligence/search",
            headers={"x-apikey": self.api_key},
            params={"query": self.query, "limit": 40},
        )
        response.raise_for_status()
        return [record for item in response.json().get("data", []) if (record := self._item_to_record(item))]

    async def lookup_indicator(self, indicator: str, endpoint: str = "files") -> FeedRecord | None:
        """Free-tier observable lookup (4 requests/min rate limit)."""
        response = await self.client.get(
            f"https://www.virustotal.com/api/v3/{endpoint}/{indicator}",
            headers={"x-apikey": self.api_key},
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json().get("data", {})
        return self._item_to_record(data)

    async def aclose(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    @staticmethod
    def _item_to_record(item: Mapping[str, Any]) -> FeedRecord | None:
        indicator = item.get("id")
        if not indicator:
            return None
        attributes = item.get("attributes", {})

        stats = attributes.get("last_analysis_stats")
        if isinstance(stats, dict) and sum(stats.values()) > 0:
            malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values())
            confidence = min(100.0, max(0.0, (malicious / total) * 100.0))
        else:
            reputation = attributes.get("reputation", 0)
            confidence = min(100.0, max(0.0, (float(reputation) + 100.0) / 2.0)) if isinstance(reputation, (int, float)) else 0.0

        tags = [str(t) for t in attributes.get("tags", [])]

        return {
            "indicator": indicator,
            "confidence_score": round(confidence, 1),
            "threat_tags": tags,
            "record_id": indicator,
            "source_url": f"https://www.virustotal.com/gui/{item.get('type', 'file')}/{indicator}",
            "last_seen": attributes.get("last_modification_date"),
            "raw_metadata": {"vt_type": item.get("type"), "vt_attributes": attributes},
        }
