from collections.abc import Sequence
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING, IndexModel

from app.models.ioc import IOC, IndicatorType, ProviderName, ThreatTag
from app.services.deduplication import merge_iocs


class IOCRepository:
    def __init__(self, db: AsyncIOMotorDatabase[Any]) -> None:
        self.db = db
        self.collection: AsyncIOMotorCollection[Any] = db["iocs"]

    async def ensure_indexes(self) -> None:
        """Create required indexes for efficient querying and strict deduplication."""
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

    async def upsert_ioc(self, incoming: IOC) -> IOC:
        """Insert a new IOC or merge into an existing IOC using deduplication logic."""
        existing_doc = await self.collection.find_one({"deduplication_key": incoming.deduplication_key})
        if existing_doc:
            # Drop MongoDB internal _id before passing to Pydantic
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

    async def upsert_batch(self, iocs: Sequence[IOC]) -> list[IOC]:
        """Upsert a list of IOCs sequentially or in batch."""
        results: list[IOC] = []
        for ioc in iocs:
            saved = await self.upsert_ioc(ioc)
            results.append(saved)
        return results

    async def get_by_key(self, deduplication_key: str) -> IOC | None:
        """Retrieve a single IOC by its unique canonical key."""
        doc = await self.collection.find_one({"deduplication_key": deduplication_key.strip().lower()})
        if not doc:
            return None
        doc.pop("_id", None)
        return IOC(**doc)

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

        cursor = self.collection.find(query).sort("last_seen", DESCENDING).skip(skip).limit(limit)
        results: list[IOC] = []
        async for doc in cursor:
            doc.pop("_id", None)
            results.append(IOC(**doc))
        return results

    async def get_metrics(self) -> dict[str, Any]:
        """Calculate aggregate SOC metrics from the stored IOC collection."""
        total = await self.collection.count_documents({})
        high_conf = await self.collection.count_documents({"confidence_score": {"$gte": 80.0}})

        # Aggregate counts by indicator_type
        type_pipeline = [{"$group": {"_id": "$indicator_type", "count": {"$sum": 1}}}]
        types_cursor = self.collection.aggregate(type_pipeline)
        by_type: dict[str, int] = {}
        async for item in types_cursor:
            if item.get("_id"):
                by_type[str(item["_id"])] = item["count"]

        # Aggregate counts by threat_tags
        tags_pipeline = [
            {"$unwind": "$threat_tags"},
            {"$group": {"_id": "$threat_tags", "count": {"$sum": 1}}},
        ]
        tags_cursor = self.collection.aggregate(tags_pipeline)
        by_tag: dict[str, int] = {}
        async for item in tags_cursor:
            if item.get("_id"):
                by_tag[str(item["_id"])] = item["count"]

        # Aggregate counts by provider
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
