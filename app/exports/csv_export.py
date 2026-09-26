import csv
import io
from collections.abc import Sequence

from app.models.ioc import IOC


def export_iocs_to_csv(iocs: Sequence[IOC]) -> str:
    """Serialize a sequence of IOC models into a clean, analyst-friendly CSV format."""
    output = io.StringIO()
    fieldnames = [
        "indicator",
        "indicator_type",
        "threat_tags",
        "confidence_score",
        "first_seen",
        "last_seen",
        "sources",
        "sources_count",
        "created_at",
        "updated_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for ioc in iocs:
        writer.writerow(
            {
                "indicator": ioc.indicator,
                "indicator_type": ioc.indicator_type.value,
                "threat_tags": "; ".join(tag.value for tag in ioc.threat_tags),
                "confidence_score": ioc.confidence_score,
                "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else "",
                "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else "",
                "sources": ", ".join(sorted({s.provider.value for s in ioc.sources})),
                "sources_count": len(ioc.sources),
                "created_at": ioc.created_at.isoformat(),
                "updated_at": ioc.updated_at.isoformat(),
            }
        )

    return output.getvalue()
