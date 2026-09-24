from datetime import datetime, timezone
from typing import Sequence

from app.models.ioc import IOC, SourceEvidence, ThreatTag


def calculate_aggregate_confidence(sources: Sequence[SourceEvidence]) -> float:
    """Calculate an aggregate confidence score with multi-source corroboration boost.

    - Uses a combination of the highest provider confidence and average provider confidence.
    - Adds a corroboration bonus (+10 per additional distinct provider).
    - Clamped strictly between 0 and 100.
    """
    scores = [s.confidence_score for s in sources if s.confidence_score is not None]
    if not scores:
        return 0.0

    distinct_providers = len({s.provider for s in sources})
    max_score = max(scores)
    avg_score = sum(scores) / len(scores)

    # Base score weights peak confidence heavily while factoring average
    base_score = (max_score * 0.7) + (avg_score * 0.3)

    # Multi-source corroboration boost (+10 per extra distinct provider)
    multi_source_boost = (distinct_providers - 1) * 10.0

    return min(100.0, max(0.0, round(base_score + multi_source_boost, 1)))


def merge_sources(
    existing_sources: Sequence[SourceEvidence],
    incoming_sources: Sequence[SourceEvidence],
) -> list[SourceEvidence]:
    """Merge incoming provider evidence into existing source list, updating same-provider entries or appending new ones."""
    source_map: dict[str, SourceEvidence] = {s.provider.value: s for s in existing_sources}

    for incoming in incoming_sources:
        key = incoming.provider.value
        if key not in source_map:
            source_map[key] = incoming
        else:
            existing = source_map[key]
            # Merge timestamps
            first_seen = _min_datetime(existing.first_seen, incoming.first_seen)
            last_seen = _max_datetime(existing.last_seen, incoming.last_seen)

            # Keep higher or updated confidence
            confidence = (
                incoming.confidence_score
                if incoming.confidence_score is not None
                else existing.confidence_score
            )

            # Merge metadata
            merged_meta = {**existing.metadata, **incoming.metadata}

            source_map[key] = SourceEvidence(
                provider=existing.provider,
                record_id=incoming.record_id or existing.record_id,
                source_url=incoming.source_url or existing.source_url,
                confidence_score=confidence,
                first_seen=first_seen,
                last_seen=last_seen,
                metadata=merged_meta,
            )

    return list(source_map.values())


def merge_iocs(existing: IOC, incoming: IOC) -> IOC:
    """Merge an incoming IOC record into an existing IOC document with identical deduplication_key."""
    if existing.deduplication_key != incoming.deduplication_key:
        raise ValueError(
            f"Cannot merge mismatched IOCs: {existing.deduplication_key} != {incoming.deduplication_key}"
        )

    # Merge sources
    merged_sources = merge_sources(existing.sources, incoming.sources)

    # Merge threat tags without duplicates
    merged_tags: list[ThreatTag] = []
    for tag in existing.threat_tags + incoming.threat_tags:
        if tag not in merged_tags:
            merged_tags.append(tag)

    # Compute earliest first_seen and latest last_seen
    first_seen = _min_datetime(existing.first_seen, incoming.first_seen)
    last_seen = _max_datetime(existing.last_seen, incoming.last_seen)

    # Recalculate aggregate confidence with multi-source boost
    confidence = calculate_aggregate_confidence(merged_sources)

    # Merge raw metadata safely
    merged_raw_meta = {**existing.raw_metadata, **incoming.raw_metadata}

    now = datetime.now(timezone.utc)

    return IOC(
        indicator=existing.indicator,
        indicator_type=existing.indicator_type,
        deduplication_key=existing.deduplication_key,
        threat_tags=merged_tags,
        confidence_score=confidence,
        sources=merged_sources,
        first_seen=first_seen,
        last_seen=last_seen,
        created_at=existing.created_at,
        updated_at=now,
        raw_metadata=merged_raw_meta,
    )


def _min_datetime(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


def _max_datetime(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)
