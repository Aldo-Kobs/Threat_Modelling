from __future__ import annotations

from .models import ArchitectureModel


TECHNOLOGY_MAP = {
    "actor": "client-system",
    "component": "web-application",
    "service": "application-server",
    "system": "application-server",
    "node": "application-server",
    "database": "database",
    "queue": "message-queue",
    "device": "iot-device",
    "cloud": "web-service-rest",
}


def build_threagile_yaml_model(model: ArchitectureModel) -> dict:
    assets = {}
    for alias, component in sorted(model.components.items()):
        assets[alias] = {
            "id": alias,
            "title": component.name,
            "type": TECHNOLOGY_MAP.get(component.kind, "process"),
            "trust_boundaries": component.boundaries or ["default-network"],
            "tags": component.tags,
            "out_of_scope": False,
        }

    flows = {}
    for index, flow in enumerate(model.data_flows, start=1):
        flow_id = f"flow_{index}"
        flows[flow_id] = {
            "id": flow_id,
            "source": flow.source,
            "target": flow.target,
            "description": flow.description or f"{flow.source} to {flow.target}",
            "protocol": flow.protocol,
            "authenticated": "unknown",
            "encrypted": flow.protocol in {"https", "tls", "ssh", "opcua"},
        }

    return {
        "threagile_version": "future-compatible-starter",
        "title": model.title,
        "author": {
            "name": "threatmod-automation",
        },
        "date": "2026-04-22",
        "business_criticality": "important",
        "architecture": {
            "trust_boundaries": sorted(model.boundaries) or ["default-network"],
            "components": assets,
            "data_flows": flows,
        },
        "questions_for_review": [
            "Which assets process safety-relevant or mission-critical functions?",
            "Which flows require authentication, encryption, freshness, and anti-replay controls?",
            "Where are identities, secrets, and update channels administered?",
        ],
    }

