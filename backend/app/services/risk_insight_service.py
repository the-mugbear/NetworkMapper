from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict, List

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db import models
from app.db.models_vulnerability import Vulnerability, VulnerabilitySeverity
from app.services.ports_of_interest import PORTS_OF_INTEREST, ports_by_number

logger = logging.getLogger(__name__)


SEVERITY_WEIGHTS = {
    VulnerabilitySeverity.CRITICAL: 6,
    VulnerabilitySeverity.HIGH: 4,
    VulnerabilitySeverity.MEDIUM: 2,
    VulnerabilitySeverity.LOW: 1,
    VulnerabilitySeverity.INFO: 0,
}


class RiskInsightService:
    """Aggregate high-risk exposure insights for dashboard consumption."""

    def __init__(self, db: Session):
        self.db = db
        self._ports_map = ports_by_number()

    def generate_insights(self, limit: int = 10) -> Dict[str, object]:
        port_summary = self._collect_port_exposure_summary()
        host_exposures = self._collect_host_exposures()
        vuln_hotspots = self._collect_vulnerability_hotspots(limit=limit)

        ranked_hosts = self._rank_hosts(host_exposures, vuln_hotspots, limit=limit)

        return {
            "ports_of_interest": {
                "summary": port_summary,
                "top_hosts": ranked_hosts,
            },
            "vulnerability_hotspots": vuln_hotspots,
        }

    def _collect_port_exposure_summary(self) -> List[Dict[str, object]]:
        port_numbers = [entry.port for entry in PORTS_OF_INTEREST]
        if not port_numbers:
            return []

        rows = (
            self.db.query(
                models.Port.port_number,
                func.count(func.distinct(models.Port.host_id)).label("host_count"),
            )
            .filter(
                models.Port.state == "open",
                models.Port.port_number.in_(port_numbers),
            )
            .group_by(models.Port.port_number)
            .all()
        )

        summary = []
        for row in rows:
            poi = self._ports_map.get(row.port_number)
            if not poi:
                continue
            summary.append(
                {
                    "port": poi.port,
                    "protocol": poi.protocol,
                    "label": poi.label,
                    "category": poi.category,
                    "weight": poi.weight,
                    "open_host_count": row.host_count,
                    "rationale": poi.rationale,
                    "recommended_action": poi.recommended_action,
                }
            )

        summary.sort(key=lambda item: (item["open_host_count"], item["weight"]), reverse=True)
        return summary

    def _collect_host_exposures(self) -> Dict[int, Dict[str, object]]:
        port_numbers = [entry.port for entry in PORTS_OF_INTEREST]
        if not port_numbers:
            return {}

        rows = (
            self.db.query(
                models.Host.id,
                models.Host.ip_address,
                models.Host.hostname,
                models.Port.port_number,
                models.Port.service_name,
            )
            .join(models.Port, models.Port.host_id == models.Host.id)
            .filter(
                models.Port.state == "open",
                models.Port.port_number.in_(port_numbers),
            )
            .all()
        )

        exposures: Dict[int, Dict[str, object]] = {}
        for row in rows:
            host_info = exposures.setdefault(
                row.id,
                {
                    "host_id": row.id,
                    "ip_address": row.ip_address,
                    "hostname": row.hostname,
                    "ports_of_interest": [],
                    "port_score": 0,
                },
            )

            poi = self._ports_map.get(row.port_number)
            if not poi:
                continue

            host_info["ports_of_interest"].append(
                {
                    "port": poi.port,
                    "protocol": poi.protocol,
                    "label": poi.label,
                    "service": row.service_name or "unknown",
                    "weight": poi.weight,
                    "category": poi.category,
                }
            )
            host_info["port_score"] += poi.weight

        return exposures

    def _collect_vulnerability_hotspots(self, limit: int) -> List[Dict[str, object]]:
        severity_counts = (
            self.db.query(
                Vulnerability.host_id,
                Vulnerability.severity,
                func.count(Vulnerability.id).label("count"),
            )
            .filter(
                Vulnerability.severity.in_(
                    [
                        VulnerabilitySeverity.CRITICAL,
                        VulnerabilitySeverity.HIGH,
                        VulnerabilitySeverity.MEDIUM,
                        VulnerabilitySeverity.LOW,
                    ]
                )
            )
            .group_by(Vulnerability.host_id, Vulnerability.severity)
            .all()
        )

        host_scores: Dict[int, Dict[str, object]] = defaultdict(lambda: {
            "host_id": None,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "score": 0,
        })

        host_identity = (
            self.db.query(models.Host.id, models.Host.ip_address, models.Host.hostname)
            .filter(models.Host.id.in_({row.host_id for row in severity_counts}))
            .all()
        )
        identity_map = {row.id: row for row in host_identity}

        for row in severity_counts:
            bucket = host_scores[row.host_id]
            bucket["host_id"] = row.host_id
            severity_key = row.severity.value
            bucket[severity_key] += row.count
            bucket["score"] += SEVERITY_WEIGHTS.get(row.severity, 0) * row.count

        results: List[Dict[str, object]] = []
        for host_id, data in host_scores.items():
            identity = identity_map.get(host_id)
            if not identity:
                continue

            results.append(
                {
                    "host_id": host_id,
                    "ip_address": identity.ip_address,
                    "hostname": identity.hostname,
                    "critical": data["critical"],
                    "high": data["high"],
                    "medium": data["medium"],
                    "low": data["low"],
                    "risk_score": data["score"],
                }
            )

        results.sort(key=lambda item: (item["risk_score"], item["critical"], item["high"]), reverse=True)
        return results[:limit]

    def _rank_hosts(
        self,
        exposures: Dict[int, Dict[str, object]],
        vuln_hotspots: List[Dict[str, object]],
        limit: int,
    ) -> List[Dict[str, object]]:
        if not exposures and not vuln_hotspots:
            return []

        hotspot_map = {entry["host_id"]: entry for entry in vuln_hotspots}

        combined: List[Dict[str, object]] = []
        host_ids = set(exposures.keys()) | set(hotspot_map.keys())
        if not host_ids:
            return []

        host_rows = (
            self.db.query(models.Host.id, models.Host.ip_address, models.Host.hostname)
            .filter(models.Host.id.in_(host_ids))
            .all()
        )
        identity_map = {row.id: row for row in host_rows}

        for host_id in host_ids:
            identity = identity_map.get(host_id)
            if not identity:
                continue

            exposure = exposures.get(host_id, {
                "ports_of_interest": [],
                "port_score": 0,
            })
            hotspot = hotspot_map.get(host_id, {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "risk_score": 0,
            })

            combined.append(
                {
                    "host_id": host_id,
                    "ip_address": identity.ip_address,
                    "hostname": identity.hostname,
                    "ports_of_interest": exposure.get("ports_of_interest", []),
                    "critical": hotspot.get("critical", 0),
                    "high": hotspot.get("high", 0),
                    "medium": hotspot.get("medium", 0),
                    "low": hotspot.get("low", 0),
                    "risk_score": exposure.get("port_score", 0) + hotspot.get("risk_score", 0),
                    "port_score": exposure.get("port_score", 0),
                    "vulnerability_score": hotspot.get("risk_score", 0),
                }
            )

        combined.sort(key=lambda item: item["risk_score"], reverse=True)
        return combined[:limit]

