from collections.abc import Mapping
from typing import Any, Protocol


FeedRecord = Mapping[str, Any]


class FeedAdapter(Protocol):
    async def fetch(self) -> list[FeedRecord]:
        """Fetch provider records and return untrusted, provider-shaped mappings."""
