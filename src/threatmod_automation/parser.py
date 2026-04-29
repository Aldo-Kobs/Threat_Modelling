from __future__ import annotations

import re

from .models import ArchitectureModel, Component, DataFlow


DECLARATION_RE = re.compile(
    r'^(?P<kind>actor|component|database|queue|node|cloud|system|device|service)\s+'
    r'(?:"(?P<name_q>[^"]+)"|(?P<name_bare>[A-Za-z0-9_.:-]+))'
    r'(?:\s+as\s+(?P<alias>[A-Za-z0-9_.:-]+))?'
)
BOUNDARY_RE = re.compile(
    r'^(?P<kind>package|node|cloud|frame|rectangle|zone|network)\s+'
    r'(?:"(?P<name_q>[^"]+)"|(?P<name_bare>[A-Za-z0-9_.:-]+))'
    r'(?:\s+as\s+(?P<alias>[A-Za-z0-9_.:-]+))?'
    r'\s*\{'
)
RELATION_RE = re.compile(
    r'^(?P<src>[A-Za-z0-9_.:-]+)\s*'
    r'(?P<arrow><<?[-.]+>?|<?[-.]+>>?)\s*'
    r'(?P<dst>[A-Za-z0-9_.:-]+)'
    r'(?:\s*:\s*(?P<label>.+))?$'
)
TITLE_RE = re.compile(r"^title\s+(?P<title>.+)$", re.IGNORECASE)

PROTOCOL_HINTS = {
    "http": "https",
    "https": "https",
    "tls": "tls",
    "mqtt": "mqtt",
    "can": "can",
    "ethernet": "ethernet",
    "udp": "udp",
    "tcp": "tcp",
    "ssh": "ssh",
    "opcua": "opcua",
}


def parse_plantuml(text: str) -> ArchitectureModel:
    model = ArchitectureModel(title="Threat Model from UML")
    boundary_stack: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("'") or line.startswith("//"):
            continue
        if line.startswith("@start") or line.startswith("@end"):
            continue

        title_match = TITLE_RE.match(line)
        if title_match:
            model.title = title_match.group("title").strip()
            continue

        boundary_match = BOUNDARY_RE.match(line)
        if boundary_match:
            boundary_name = boundary_match.group("name_q") or boundary_match.group("name_bare")
            model.boundaries.add(boundary_name)
            boundary_stack.append(boundary_name)
            continue

        if line == "}":
            if boundary_stack:
                boundary_stack.pop()
            continue

        declaration_match = DECLARATION_RE.match(line)
        if declaration_match:
            kind = declaration_match.group("kind")
            name = declaration_match.group("name_q") or declaration_match.group("name_bare")
            alias = declaration_match.group("alias") or _default_alias(name)
            model.components[alias] = Component(
                alias=alias,
                name=name,
                kind=kind,
                boundaries=list(boundary_stack),
                tags=_infer_tags(name, kind),
            )
            continue

        relation_match = RELATION_RE.match(line)
        if relation_match:
            label = (relation_match.group("label") or "").strip()
            model.data_flows.append(
                DataFlow(
                    source=relation_match.group("src"),
                    target=relation_match.group("dst"),
                    direction=relation_match.group("arrow"),
                    description=label,
                    protocol=_infer_protocol(label),
                )
            )

    return model


def _infer_protocol(label: str) -> str:
    lower_label = label.lower()
    for hint, protocol in PROTOCOL_HINTS.items():
        if hint in lower_label:
            return protocol
    return "unknown"


def _default_alias(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").lower() or "component"


def _infer_tags(name: str, kind: str) -> list[str]:
    tokens = f"{name} {kind}".lower()
    tags: set[str] = set()
    if any(token in tokens for token in ("vehicle", "ecu", "plc", "controller", "sensor", "actuator")):
        tags.add("operational-technology")
    if any(token in tokens for token in ("gateway", "router", "switch", "firewall")):
        tags.add("network-infrastructure")
    if any(token in tokens for token in ("db", "database", "storage", "vault")):
        tags.add("data-store")
    if any(token in tokens for token in ("user", "operator", "driver", "admin", "maintainer")):
        tags.add("human-user")
    if any(token in tokens for token in ("cloud", "backend", "api", "service")):
        tags.add("it-service")
    return sorted(tags)

