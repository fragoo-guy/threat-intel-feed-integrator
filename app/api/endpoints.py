from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import JSONResponse

from app.api.deps import get_feed_scheduler, get_ioc_repo
from app.db.repository import IOCRepository
from app.exports.csv_export import export_iocs_to_csv
from app.exports.stix_export import export_iocs_to_stix
from app.models.ioc import IOC, IndicatorType, ProviderName, ThreatTag
from app.services.ingestion import IngestionService
from app.services.scheduler import ThreatFeedScheduler

router = APIRouter()


@router.get("/health", tags=["System"])
async def get_health_status() -> dict[str, Any]:
    """Return application system health and latest threat feed sync status."""
    feed_health = IngestionService.get_feed_health()
    return {
        "status": "ok",
        "service": "threat-intel-feed-integrator",
        "feeds": feed_health,
    }


@router.get("/metrics", tags=["Analytics"])
async def get_soc_metrics(
    repo: IOCRepository = Depends(get_ioc_repo),
) -> dict[str, Any]:
    """Return high-level SOC threat metrics and indicator distributions."""
    return await repo.get_metrics()


@router.get("/iocs", response_model=list[IOC], tags=["IOCs"])
async def list_iocs(
    indicator: str | None = Query(default=None, description="Search indicator by regex or substring"),
    indicator_type: IndicatorType | None = Query(default=None, description="Filter by indicator type"),
    tag: ThreatTag | None = Query(default=None, description="Filter by threat tag"),
    provider: ProviderName | None = Query(default=None, description="Filter by source feed provider"),
    min_confidence: float | None = Query(default=None, ge=0.0, le=100.0, description="Minimum confidence score"),
    limit: int = Query(default=50, ge=1, le=1000, description="Page size limit"),
    skip: int = Query(default=0, ge=0, description="Offset pagination"),
    repo: IOCRepository = Depends(get_ioc_repo),
) -> list[IOC]:
    """Retrieve normalized and deduplicated IOCs with filtering and pagination."""
    return await repo.query_iocs(
        indicator=indicator,
        indicator_type=indicator_type,
        tag=tag,
        provider=provider,
        min_confidence=min_confidence,
        limit=limit,
        skip=skip,
    )


@router.get("/iocs/{deduplication_key:path}", response_model=IOC, tags=["IOCs"])
async def get_ioc_detail(
    deduplication_key: str,
    repo: IOCRepository = Depends(get_ioc_repo),
) -> IOC:
    """Retrieve full details, source evidence, and metadata for a specific IOC."""
    ioc = await repo.get_by_key(deduplication_key)
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IOC with key '{deduplication_key}' not found",
        )
    return ioc


@router.post("/feeds/{provider}/sync", tags=["Ingestion"])
async def trigger_feed_sync(
    provider: str,
    scheduler: ThreatFeedScheduler = Depends(get_feed_scheduler),
) -> dict[str, Any]:
    """Trigger an immediate on-demand ingestion run for a specific feed adapter."""
    valid_providers = {"otx", "abuseipdb", "virustotal"}
    prov = provider.strip().lower()
    if prov not in valid_providers:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid provider '{provider}'. Supported providers: {sorted(valid_providers)}",
        )

    try:
        result = await scheduler.run_feed_now(prov)
        return {"provider": prov, "result": result}
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute ingestion for {provider}: {exc}",
        )


@router.get("/export/csv", tags=["Exports"])
async def export_csv(
    indicator: str | None = Query(default=None),
    indicator_type: IndicatorType | None = Query(default=None),
    tag: ThreatTag | None = Query(default=None),
    provider: ProviderName | None = Query(default=None),
    min_confidence: float | None = Query(default=None, ge=0.0, le=100.0),
    limit: int = Query(default=1000, ge=1, le=5000),
    repo: IOCRepository = Depends(get_ioc_repo),
) -> Response:
    """Export filtered IOCs as an analyst-friendly CSV spreadsheet."""
    iocs = await repo.query_iocs(
        indicator=indicator,
        indicator_type=indicator_type,
        tag=tag,
        provider=provider,
        min_confidence=min_confidence,
        limit=limit,
        skip=0,
    )
    csv_content = export_iocs_to_csv(iocs)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="iocs_export.csv"'},
    )


@router.get("/export/stix", tags=["Exports"])
async def export_stix(
    indicator: str | None = Query(default=None),
    indicator_type: IndicatorType | None = Query(default=None),
    tag: ThreatTag | None = Query(default=None),
    provider: ProviderName | None = Query(default=None),
    min_confidence: float | None = Query(default=None, ge=0.0, le=100.0),
    limit: int = Query(default=1000, ge=1, le=5000),
    repo: IOCRepository = Depends(get_ioc_repo),
) -> JSONResponse:
    """Export filtered IOCs as a standardized STIX 2.1 JSON bundle for SIEM/SOAR."""
    iocs = await repo.query_iocs(
        indicator=indicator,
        indicator_type=indicator_type,
        tag=tag,
        provider=provider,
        min_confidence=min_confidence,
        limit=limit,
        skip=0,
    )
    stix_bundle = export_iocs_to_stix(iocs)
    return JSONResponse(
        content=stix_bundle,
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="stix2_bundle.json"'},
    )
