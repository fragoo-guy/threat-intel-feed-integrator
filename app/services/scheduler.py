import logging
import os
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.db.mongodb import get_db
from app.db.repository import IOCRepository
from app.feeds.abuseipdb import AbuseIPDBAdapter
from app.feeds.otx import OTXAdapter
from app.feeds.virustotal import VirusTotalAdapter
from app.services.ingestion import IngestionService

logger = logging.getLogger(__name__)


class ThreatFeedScheduler:
    def __init__(self) -> None:
        self.scheduler = AsyncIOScheduler()
        self._is_running = False

    def setup_jobs(self) -> None:
        """Register periodic ingestion jobs for available provider adapters."""
        otx_key = os.getenv("OTX_API_KEY", "")
        abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
        vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")

        # Default poll intervals in minutes
        otx_interval = int(os.getenv("OTX_POLL_INTERVAL_MINUTES", "60"))
        abuse_interval = int(os.getenv("ABUSEIPDB_POLL_INTERVAL_MINUTES", "120"))
        vt_interval = int(os.getenv("VIRUSTOTAL_POLL_INTERVAL_MINUTES", "240"))

        if otx_key:
            self.scheduler.add_job(
                self._run_otx_job,
                "interval",
                minutes=otx_interval,
                id="job_otx",
                replace_existing=True,
            )
            logger.info("Registered OTX ingestion job (every %d mins)", otx_interval)

        if abuse_key:
            self.scheduler.add_job(
                self._run_abuseipdb_job,
                "interval",
                minutes=abuse_interval,
                id="job_abuseipdb",
                replace_existing=True,
            )
            logger.info("Registered AbuseIPDB ingestion job (every %d mins)", abuse_interval)

        if vt_key:
            self.scheduler.add_job(
                self._run_virustotal_job,
                "interval",
                minutes=vt_interval,
                id="job_virustotal",
                replace_existing=True,
            )
            logger.info("Registered VirusTotal ingestion job (every %d mins)", vt_interval)

    async def run_feed_now(self, provider_name: str) -> dict[str, Any]:
        """Trigger an immediate, on-demand ingestion run for a specific provider."""
        provider = provider_name.strip().lower()
        if provider == "otx":
            return await self._run_otx_job()
        elif provider == "abuseipdb":
            return await self._run_abuseipdb_job()
        elif provider == "virustotal":
            return await self._run_virustotal_job()
        else:
            raise ValueError(f"Unknown threat provider: {provider_name}")

    async def _run_otx_job(self) -> dict[str, Any]:
        otx_key = os.getenv("OTX_API_KEY", "")
        if not otx_key:
            logger.warning("OTX API key not configured; skipping job")
            return {"status": "skipped", "reason": "missing_api_key"}

        repo = IOCRepository(get_db())
        service = IngestionService(repo)
        adapter = OTXAdapter(api_key=otx_key)
        try:
            return await service.ingest_feed(adapter)
        finally:
            await adapter.aclose()

    async def _run_abuseipdb_job(self) -> dict[str, Any]:
        abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
        if not abuse_key:
            logger.warning("AbuseIPDB API key not configured; skipping job")
            return {"status": "skipped", "reason": "missing_api_key"}

        repo = IOCRepository(get_db())
        service = IngestionService(repo)
        adapter = AbuseIPDBAdapter(api_key=abuse_key)
        try:
            return await service.ingest_feed(adapter)
        finally:
            await adapter.aclose()

    async def _run_virustotal_job(self) -> dict[str, Any]:
        vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        if not vt_key:
            logger.warning("VirusTotal API key not configured; skipping job")
            return {"status": "skipped", "reason": "missing_api_key"}

        repo = IOCRepository(get_db())
        service = IngestionService(repo)
        adapter = VirusTotalAdapter(api_key=vt_key)
        try:
            return await service.ingest_feed(adapter)
        finally:
            await adapter.aclose()

    def start(self) -> None:
        if not self._is_running:
            self.setup_jobs()
            self.scheduler.start()
            self._is_running = True
            logger.info("Threat feed scheduler started")

    def shutdown(self) -> None:
        if self._is_running:
            self.scheduler.shutdown(wait=False)
            self._is_running = False
            logger.info("Threat feed scheduler stopped")


# Global singleton instance
feed_scheduler = ThreatFeedScheduler()
