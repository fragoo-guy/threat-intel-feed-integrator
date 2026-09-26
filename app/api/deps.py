from app.db.mongodb import get_db
from app.db.repository import IOCRepository
from app.services.scheduler import ThreatFeedScheduler, feed_scheduler


def get_ioc_repo() -> IOCRepository:
    """Dependency provider for IOC repository."""
    return IOCRepository(get_db())


def get_feed_scheduler() -> ThreatFeedScheduler:
    """Dependency provider for threat feed scheduler."""
    return feed_scheduler
