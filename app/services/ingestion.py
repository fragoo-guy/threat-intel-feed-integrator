from datetime import datetime, timezone
import logging
from typing import Any

from app.db.repository import IOCRepository
from app.feeds.base import FeedAdapter
from app.feeds.normalization import normalize_record
from app.services.tagging import enrich_threat_tags

logger = logging.getLogger(__name__)

# In-memory registry to track feed health and sync status
FEED_HEALTH: dict[str, dict[str, Any]] = {}


class IngestionService:
    def __init__(self, repo: IOCRepository) -> None:
        self.repo = repo

    async def ingest_feed(self, adapter: FeedAdapter) -> dict[str, Any]:
        """Fetch, normalize, tag, and persist records from a single threat intelligence feed."""
        provider_name = getattr(adapter, "provider", adapter.__class__.__name__).value if hasattr(getattr(adapter, "provider", None), "value") else str(getattr(adapter, "provider", adapter.__class__.__name__))

        start_time = datetime.now(timezone.utc)
        stats: dict[str, Any] = {
            "provider": provider_name,
            "status": "running",
            "start_time": start_time.isoformat(),
            "records_fetched": 0,
            "records_upserted": 0,
            "errors": 0,
            "error_message": None,
        }

        try:
            raw_records = await adapter.fetch()
            stats["records_fetched"] = len(raw_records)

            for record in raw_records:
                try:
                    # Normalize raw vendor record to canonical IOC model
                    ioc = normalize_record(record, getattr(adapter, "provider"))

                    # Enrich threat tags with contextual text clues
                    clues: list[str] = []
                    if record.get("source_metadata"):
                        clues.extend(str(v) for v in record["source_metadata"].values() if v)
                    if record.get("raw_metadata"):
                        clues.extend(str(v) for v in record["raw_metadata"].values() if v)

                    enriched_tags = enrich_threat_tags(existing_tags=ioc.threat_tags, text_clues=clues)
                    if enriched_tags != ioc.threat_tags:
                        ioc = ioc.model_copy(update={"threat_tags": enriched_tags})

                    # Persist and merge with deduplication
                    await self.repo.upsert_ioc(ioc)
                    stats["records_upserted"] += 1
                except Exception as err:
                    stats["errors"] += 1
                    logger.warning("Failed to normalize or upsert record from %s: %s", provider_name, err)

            stats["status"] = "success"
        except Exception as exc:
            stats["status"] = "failed"
            stats["error_message"] = str(exc)
            logger.error("Feed ingestion failed for %s: %s", provider_name, exc)

        end_time = datetime.now(timezone.utc)
        stats["end_time"] = end_time.isoformat()
        stats["duration_seconds"] = round((end_time - start_time).total_seconds(), 2)

        # Store in health registry
        FEED_HEALTH[provider_name] = stats
        return stats

    @classmethod
    def get_feed_health(cls) -> dict[str, dict[str, Any]]:
        """Return the current feed health status for all registered feeds."""
        return FEED_HEALTH
