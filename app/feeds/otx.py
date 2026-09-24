from collections.abc import Mapping
from typing import Any

import httpx

from app.feeds.base import FeedRecord
from app.models import ProviderName


class OTXAdapter:
    provider = ProviderName.OTX

    def __init__(self, api_key: str, client: httpx.AsyncClient | None = None) -> None:
        self.api_key = api_key
        self.client = client or httpx.AsyncClient(timeout=30.0)
        self._owns_client = client is None

    async def fetch(self) -> list[FeedRecord]:
        response = await self.client.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers={"X-OTX-API-KEY": self.api_key},
            params={"limit": 100},
        )
        response.raise_for_status()
        payload = response.json()
        records: list[FeedRecord] = []
        for pulse in payload.get("results", []):
            records.extend(self._pulse_records(pulse))
        return records

    async def aclose(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    @staticmethod
    def _pulse_records(pulse: Mapping[str, Any]) -> list[FeedRecord]:
        tags = [str(tag) for tag in pulse.get("tags", [])]
        records: list[FeedRecord] = []
        for indicator in pulse.get("indicators", []):
            value = indicator.get("indicator")
            if not value:
                continue
            records.append(
                {
                    "indicator": value,
                    "indicator_type": indicator.get("type"),
                    "confidence_score": 50,
                    "threat_tags": tags,
                    "record_id": indicator.get("id") or pulse.get("id"),
                    "source_url": f"https://otx.alienvault.com/pulse/{pulse.get('id')}" if pulse.get("id") else None,
                    "first_seen": indicator.get("created") or pulse.get("created"),
                    "last_seen": indicator.get("modified") or pulse.get("modified"),
                    "source_metadata": {"pulse_name": pulse.get("name")},
                    "raw_metadata": {"pulse_id": pulse.get("id")},
                }
            )
        return records
