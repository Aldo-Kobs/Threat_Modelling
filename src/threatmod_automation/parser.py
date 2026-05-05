from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

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

STARUML_SUFFIXES = {".mdj", ".mfj"}

STARUML_COMPONENT_KIND_MAP = {
    "C4Component": "component",
    "C4Container": "service",
    "C4Person": "actor",
    "C4SoftwareSystem": "system",
    "DFDDataStore": "database",
    "DFDExternalEntity": "actor",
    "DFDProcess": "service",
    "UMLActor": "actor",
    "UMLArtifact": "component",
    "UMLClass": "component",
    "UMLComponent": "component",
    "UMLDataStoreNode": "database",
    "UMLInterface": "service",
    "UMLNode": "node",
}

STARUML_BOUNDARY_TYPES = {
    "C4Container",
    "C4SoftwareSystem",
    "UMLNode",
    "UMLPackage",
    "UMLSubsystem",
}

STARUML_DIRECTED_RELATION_TYPES = {
    "C4Relationship",
    "DFDDataFlow",
    "UMLDependency",
}

STARUML_UNDIRECTED_RELATION_TYPES = {
    "UMLAssociation",
    "UMLCommunicationPath",
    "UMLConnector",
}


def parse_architecture(text: str, *, source_name: str | None = None) -> ArchitectureModel:
    if source_name is not None and Path(source_name).suffix.lower() in STARUML_SUFFIXES:
        return parse_staruml(text)
    return parse_plantuml(text)


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
            alias = _next_available_alias(model.components, alias)
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


def parse_staruml(text: str) -> ArchitectureModel:
    try:
        root = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid StarUML JSON input at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc

    if not isinstance(root, dict):
        raise ValueError("StarUML input must be a JSON object representing a project or fragment.")

    title = _string_value(root.get("name")) or "Threat Model from StarUML"
    model = ArchitectureModel(title=title)
    index: dict[str, dict[str, Any]] = {}
    _index_staruml_elements(root, index)

    aliases_by_element_id: dict[str, str] = {}
    for element_id, element in index.items():
        kind = _staruml_component_kind(element)
        if kind is None:
            continue

        name = _string_value(element.get("name"))
        if not name:
            continue

        alias = _next_available_alias(model.components, _default_alias(name))
        boundaries = _staruml_boundaries_for_element(element, index)
        model.components[alias] = Component(
            alias=alias,
            name=name,
            kind=kind,
            boundaries=boundaries,
            tags=_infer_tags(_staruml_metadata_text(element), kind),
        )
        aliases_by_element_id[element_id] = alias
        model.boundaries.update(boundaries)

    for element_id, element in index.items():
        flow = _staruml_data_flow(element_id, element, index, aliases_by_element_id)
        if flow is not None:
            model.data_flows.append(flow)

    return model


def _infer_protocol(label: str) -> str:
    lower_label = label.lower()
    for hint, protocol in PROTOCOL_HINTS.items():
        if hint in lower_label:
            return protocol
    return "unknown"


def _default_alias(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").lower() or "component"


def _next_available_alias(components: dict[str, Component], preferred: str) -> str:
    candidate = preferred or "component"
    if candidate not in components:
        return candidate

    counter = 2
    while True:
        numbered = f"{candidate}_{counter}"
        if numbered not in components:
            return numbered
        counter += 1


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


def _index_staruml_elements(value: Any, index: dict[str, dict[str, Any]]) -> None:
    if isinstance(value, dict):
        value_id = value.get("_id")
        if isinstance(value_id, str):
            index[value_id] = value
        for nested in value.values():
            _index_staruml_elements(nested, index)
        return

    if isinstance(value, list):
        for item in value:
            _index_staruml_elements(item, index)


def _staruml_component_kind(element: dict[str, Any]) -> str | None:
    element_type = _string_value(element.get("_type"))
    base_kind = STARUML_COMPONENT_KIND_MAP.get(element_type)
    if base_kind is None:
        return None

    tokens = _staruml_metadata_text(element).lower()
    if any(token in tokens for token in ("database", "db", "datastore", "historian", "ledger", "vault", "repository")):
        return "database"
    if any(token in tokens for token in ("queue", "broker", "topic", "stream", "bus")):
        return "queue"
    if any(token in tokens for token in ("cloud", "aws", "azure", "gcp", "saas")):
        return "cloud"
    if any(token in tokens for token in ("device", "sensor", "actuator", "ecu", "plc", "controller")):
        return "device"
    if base_kind in {"component", "node", "system"} and any(
        token in tokens for token in ("service", "api", "backend", "microservice")
    ):
        return "service"
    return base_kind


def _staruml_boundaries_for_element(
    element: dict[str, Any],
    index: dict[str, dict[str, Any]],
) -> list[str]:
    boundaries: list[str] = []
    current = _staruml_parent_element(element, index)

    while current is not None:
        current_type = _string_value(current.get("_type"))
        current_name = _string_value(current.get("name"))
        if current_type in STARUML_BOUNDARY_TYPES and current_name:
            boundaries.append(current_name)
        current = _staruml_parent_element(current, index)

    boundaries.reverse()
    return boundaries


def _staruml_data_flow(
    element_id: str,
    element: dict[str, Any],
    index: dict[str, dict[str, Any]],
    aliases_by_element_id: dict[str, str],
) -> DataFlow | None:
    element_type = _string_value(element.get("_type"))

    if element_type in STARUML_DIRECTED_RELATION_TYPES:
        source = _staruml_resolve_component_alias(element.get("source"), index, aliases_by_element_id)
        target = _staruml_resolve_component_alias(element.get("target"), index, aliases_by_element_id)
        direction = "-->"
    elif element_type in STARUML_UNDIRECTED_RELATION_TYPES:
        source = _staruml_resolve_component_alias(_staruml_relation_end_reference(element.get("end1")), index, aliases_by_element_id)
        target = _staruml_resolve_component_alias(_staruml_relation_end_reference(element.get("end2")), index, aliases_by_element_id)
        direction = "--"
    else:
        return None

    if source is None or target is None or source == target:
        return None

    label = _staruml_relation_label(element)
    return DataFlow(
        source=source,
        target=target,
        direction=direction,
        description=label,
        protocol=_infer_protocol(label),
    )


def _staruml_resolve_component_alias(
    reference: Any,
    index: dict[str, dict[str, Any]],
    aliases_by_element_id: dict[str, str],
) -> str | None:
    current = _staruml_resolve_ref(reference, index)

    while current is not None:
        current_id = _string_value(current.get("_id"))
        if current_id in aliases_by_element_id:
            return aliases_by_element_id[current_id]
        current = _staruml_parent_element(current, index)

    return None


def _staruml_relation_end_reference(end: Any) -> Any:
    if not isinstance(end, dict):
        return None
    return end.get("reference")


def _staruml_parent_element(
    element: dict[str, Any],
    index: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    return _staruml_resolve_ref(element.get("_parent"), index)


def _staruml_resolve_ref(reference: Any, index: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    if not isinstance(reference, dict):
        return None

    ref_id = reference.get("$ref")
    if isinstance(ref_id, str):
        return index.get(ref_id)

    inline_id = reference.get("_id")
    if isinstance(inline_id, str):
        return index.get(inline_id, reference)

    return None


def _staruml_relation_label(element: dict[str, Any]) -> str:
    for key in ("description", "name", "stereotype"):
        value = _string_value(element.get(key))
        if value:
            return value
    return ""


def _staruml_metadata_text(element: dict[str, Any]) -> str:
    pieces = [
        _string_value(element.get("_type")),
        _string_value(element.get("name")),
        _string_value(element.get("stereotype")),
        _string_value(element.get("description")),
        _string_value(element.get("technology")),
        _string_value(element.get("kind")),
    ]
    return " ".join(piece for piece in pieces if piece)


def _string_value(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""
