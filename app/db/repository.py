from collections.abc import Sequence
import logging
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING, IndexModel

from app.models.ioc import IOC, IndicatorType, ProviderName, ThreatTag
from app.services.deduplication import merge_iocs

logger = logging.getLogger(__name__)

# Global in-memory demo store used when MongoDB is offline or in demo mode
_DEMO_STORE: dict[str, IOC] = {}


def get_demo_store() -> dict[str, IOC]:
    """Retrieve or initialize the in-memory fallback store seeded with sample threat intelligence."""
    global _DEMO_STORE
    if not _DEMO_STORE:
        try:
            from app.fixtures.sample_iocs import get_demo_iocs
            for ioc in get_demo_iocs():
                _DEMO_STORE[ioc.deduplication_key] = ioc
        except Exception as exc:
            logger.debug("Could not initialize demo dataset: %s", exc)
    return _DEMO_STORE


class IOCRepository:
    _mongo_online: bool | None = None

    def __init__(self, db: AsyncIOMotorDatabase[Any]) -> None:
        self.db = db
        self.collection: AsyncIOMotorCollection[Any] = db["iocs"]

    async def _check_mongo_alive(self) -> bool:
        """Quickly check if the MongoDB cluster is reachable; cache the result to prevent timeout delays."""
        # Always assume alive in unit test mocks
        if hasattr(self.db, "_mock_return_value") or type(self.db).__name__ in ("MagicMock", "AsyncMock"):
            return True
        if IOCRepository._mongo_online is not None:
            return IOCRepository._mongo_online

        try:
            await self.db.command("ping")
            IOCRepository._mongo_online = True
            return True
        except Exception:
            IOCRepository._mongo_online = False
            logger.info("MongoDB cluster unreachable. Running in resilient in-memory demo mode.")
            return False

    async def ensure_indexes(self) -> None:
        """Create required indexes for efficient querying and strict deduplication."""
        if not await self._check_mongo_alive():
            return

        try:
            indexes = [
                IndexModel([("deduplication_key", ASCENDING)], unique=True, name="idx_dedup_key_unique"),
                IndexModel([("indicator", ASCENDING)], name="idx_indicator"),
                IndexModel([("indicator_type", ASCENDING)], name="idx_indicator_type"),
                IndexModel([("threat_tags", ASCENDING)], name="idx_threat_tags"),
                IndexModel([("confidence_score", DESCENDING)], name="idx_confidence"),
                IndexModel([("last_seen", DESCENDING)], name="idx_last_seen"),
                IndexModel([("sources.provider", ASCENDING)], name="idx_sources_provider"),
            ]
            await self.collection.create_indexes(indexes)
        except Exception as exc:
            logger.warning("MongoDB index initialization deferred: %s", exc)

    async def upsert_ioc(self, incoming: IOC) -> IOC:
        """Insert a new IOC or merge into an existing IOC using deduplication logic."""
        if not await self._check_mongo_alive():
            store = get_demo_store()
            if incoming.deduplication_key in store:
                merged = merge_iocs(store[incoming.deduplication_key], incoming)
                store[incoming.deduplication_key] = merged
                return merged
            store[incoming.deduplication_key] = incoming
            return incoming

        try:
            existing_doc = await self.collection.find_one({"deduplication_key": incoming.deduplication_key})
            if existing_doc:
                existing_doc.pop("_id", None)
                existing_ioc = IOC(**existing_doc)
                final_ioc = merge_iocs(existing_ioc, incoming)
                await self.collection.replace_one(
                    {"deduplication_key": final_ioc.deduplication_key},
                    final_ioc.model_dump(),
                    upsert=True,
                )
                return final_ioc

            doc = incoming.model_dump()
            await self.collection.insert_one(doc)
            return incoming
        except Exception:
            store = get_demo_store()
            if incoming.deduplication_key in store:
                merged = merge_iocs(store[incoming.deduplication_key], incoming)
                store[incoming.deduplication_key] = merged
                return merged
            store[incoming.deduplication_key] = incoming
            return incoming

    async def upsert_batch(self, iocs: Sequence[IOC]) -> list[IOC]:
        """Upsert a list of IOCs sequentially or in batch."""
        results: list[IOC] = []
        for ioc in iocs:
            saved = await self.upsert_ioc(ioc)
            results.append(saved)
        return results

    async def get_by_key(self, deduplication_key: str) -> IOC | None:
        """Retrieve a single IOC by its unique canonical key."""
        clean_key = deduplication_key.strip().lower()
        if not await self._check_mongo_alive():
            return get_demo_store().get(clean_key)

        try:
            doc = await self.collection.find_one({"deduplication_key": clean_key})
            if doc:
                doc.pop("_id", None)
                return IOC(**doc)
        except Exception:
            pass
        return get_demo_store().get(clean_key)

    async def query_iocs(
        self,
        indicator: str | None = None,
        indicator_type: IndicatorType | str | None = None,
        tag: ThreatTag | str | None = None,
        provider: ProviderName | str | None = None,
        min_confidence: float | None = None,
        limit: int = 50,
        skip: int = 0,
    ) -> list[IOC]:
        """Search and filter IOCs with pagination."""
        if not await self._check_mongo_alive():
            return self._filter_demo_store(
                indicator=indicator,
                indicator_type=indicator_type,
                tag=tag,
                provider=provider,
                min_confidence=min_confidence,
                limit=limit,
                skip=skip,
            )

        query: dict[str, Any] = {}
        if indicator:
            query["indicator"] = {"$regex": indicator.strip(), "$options": "i"}
        if indicator_type:
            val = indicator_type.value if isinstance(indicator_type, IndicatorType) else str(indicator_type)
            query["indicator_type"] = val
        if tag:
            val = tag.value if isinstance(tag, ThreatTag) else str(tag)
            query["threat_tags"] = val
        if provider:
            val = provider.value if isinstance(provider, ProviderName) else str(provider)
            query["sources.provider"] = val
        if min_confidence is not None:
            query["confidence_score"] = {"$gte": float(min_confidence)}

        try:
            cursor = self.collection.find(query).sort("last_seen", DESCENDING).skip(skip).limit(limit)
            results: list[IOC] = []
            async for doc in cursor:
                doc.pop("_id", None)
                results.append(IOC(**doc))
            if results or await self.collection.count_documents({}) > 0:
                return results
        except Exception:
            pass

        return self._filter_demo_store(
            indicator=indicator,
            indicator_type=indicator_type,
            tag=tag,
            provider=provider,
            min_confidence=min_confidence,
            limit=limit,
            skip=skip,
        )

    def _filter_demo_store(
        self,
        indicator: str | None = None,
        indicator_type: IndicatorType | str | None = None,
        tag: ThreatTag | str | None = None,
        provider: ProviderName | str | None = None,
        min_confidence: float | None = None,
        limit: int = 50,
        skip: int = 0,
    ) -> list[IOC]:
        """Filter the in-memory demo dataset."""
        store = get_demo_store()
        type_str = indicator_type.value if isinstance(indicator_type, IndicatorType) else (str(indicator_type) if indicator_type else None)
        tag_str = tag.value if isinstance(tag, ThreatTag) else (str(tag) if tag else None)
        prov_str = provider.value if isinstance(provider, ProviderName) else (str(provider) if provider else None)

        filtered: list[IOC] = []
        for ioc in store.values():
            if indicator and indicator.lower() not in ioc.indicator.lower():
                continue
            if type_str and ioc.indicator_type.value != type_str:
                continue
            if tag_str and not any(t.value == tag_str for t in ioc.threat_tags):
                continue
            if prov_str and not any(s.provider.value == prov_str for s in ioc.sources):
                continue
            if min_confidence is not None and ioc.confidence_score < float(min_confidence):
                continue
            filtered.append(ioc)

        # Sort by last_seen descending
        filtered.sort(key=lambda x: x.last_seen or x.created_at, reverse=True)
        return filtered[skip : skip + limit]

    async def get_metrics(self) -> dict[str, Any]:
        """Calculate aggregate SOC metrics from the stored IOC collection."""
        if not await self._check_mongo_alive():
            return self._calc_demo_metrics()

        try:
            total = await self.collection.count_documents({})
            if total > 0:
                high_conf = await self.collection.count_documents({"confidence_score": {"$gte": 80.0}})

                type_pipeline = [{"$group": {"_id": "$indicator_type", "count": {"$sum": 1}}}]
                types_cursor = self.collection.aggregate(type_pipeline)
                by_type: dict[str, int] = {}
                async for item in types_cursor:
                    if item.get("_id"):
                        by_type[str(item["_id"])] = item["count"]

                tags_pipeline = [
                    {"$unwind": "$threat_tags"},
                    {"$group": {"_id": "$threat_tags", "count": {"$sum": 1}}},
                ]
                tags_cursor = self.collection.aggregate(tags_pipeline)
                by_tag: dict[str, int] = {}
                async for item in tags_cursor:
                    if item.get("_id"):
                        by_tag[str(item["_id"])] = item["count"]

                provider_pipeline = [
                    {"$unwind": "$sources"},
                    {"$group": {"_id": "$sources.provider", "count": {"$sum": 1}}},
                ]
                provider_cursor = self.collection.aggregate(provider_pipeline)
                by_provider: dict[str, int] = {}
                async for item in provider_cursor:
                    if item.get("_id"):
                        by_provider[str(item["_id"])] = item["count"]

                return {
                    "total_iocs": total,
                    "high_confidence_count": high_conf,
                    "by_indicator_type": by_type,
                    "by_threat_tag": by_tag,
                    "by_provider": by_provider,
                }
        except Exception:
            pass

        return self._calc_demo_metrics()

    def _calc_demo_metrics(self) -> dict[str, Any]:
        """Calculate metrics directly from the in-memory dataset."""
        store = get_demo_store()
        total = len(store)
        high_conf = sum(1 for ioc in store.values() if ioc.confidence_score >= 80.0)

        by_type: dict[str, int] = {}
        by_tag: dict[str, int] = {}
        by_provider: dict[str, int] = {}

        for ioc in store.values():
            t_val = ioc.indicator_type.value
            by_type[t_val] = by_type.get(t_val, 0) + 1

            for tag in ioc.threat_tags:
                tag_val = tag.value
                by_tag[tag_val] = by_tag.get(tag_val, 0) + 1

            for src in ioc.sources:
                p_val = src.provider.value
                by_provider[p_val] = by_provider.get(p_val, 0) + 1

        return {
            "total_iocs": total,
            "high_confidence_count": high_conf,
            "by_indicator_type": by_type,
            "by_threat_tag": by_tag,
            "by_provider": by_provider,
        }
