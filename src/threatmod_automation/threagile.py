from __future__ import annotations

import os
import shutil
import subprocess
import time
from datetime import date
from pathlib import Path

from .models import ArchitectureModel


DEFAULT_THREAGILE_IMAGE = "threagile/threagile"
THREAGILE_WORKDIR = Path("/app/work")

TECHNOLOGY_MAP = {
    "actor": "client-system",
    "component": "web-application",
    "service": "web-service-rest",
    "system": "web-application",
    "node": "web-application",
    "database": "database",
    "queue": "message-queue",
    "device": "iot-device",
    "cloud": "web-service-rest",
}

TECHNICAL_ASSET_TYPE_MAP = {
    "actor": "external-entity",
    "database": "datastore",
    "queue": "datastore",
}

TECHNICAL_ASSET_SIZE_MAP = {
    "actor": "system",
    "service": "service",
    "system": "system",
    "node": "system",
    "cloud": "system",
}

PROTOCOL_MAP = {
    "http": "http",
    "https": "https",
    "tls": "binary-encrypted",
    "mqtt": "mqtt",
    "can": "binary",
    "ethernet": "binary",
    "udp": "binary",
    "tcp": "binary",
    "ssh": "ssh",
    "opcua": "binary-encrypted",
    "unknown": "unknown-protocol",
}

STORAGE_KINDS = {"database", "queue"}


def build_threagile_yaml_model(model: ArchitectureModel) -> dict:
    sorted_components = sorted(model.components.items())
    boundary_ids = {name: _slugify(name) for name in sorted(model.boundaries)}
    boundary_children = {name: set() for name in boundary_ids}

    for component in model.components.values():
        for parent, child in zip(component.boundaries, component.boundaries[1:]):
            if parent in boundary_children and child in boundary_ids:
                boundary_children[parent].add(child)

    inferred_data_assets = _build_data_assets(model)
    processed_assets_by_component = {alias: set() for alias in model.components}
    stored_assets_by_component = {alias: set() for alias in model.components}
    communication_links_by_component = {alias: {} for alias in model.components}

    for index, inferred_asset in enumerate(inferred_data_assets, start=1):
        flow = inferred_asset["flow"]
        data_asset_id = inferred_asset["asset"]["id"]

        if flow is not None:
            if flow.source in processed_assets_by_component:
                processed_assets_by_component[flow.source].add(data_asset_id)
            if flow.target in processed_assets_by_component:
                processed_assets_by_component[flow.target].add(data_asset_id)
            if flow.source in model.components and model.components[flow.source].kind in STORAGE_KINDS:
                stored_assets_by_component[flow.source].add(data_asset_id)
            if flow.target in model.components and model.components[flow.target].kind in STORAGE_KINDS:
                stored_assets_by_component[flow.target].add(data_asset_id)

            if flow.source in communication_links_by_component and flow.target in model.components:
                communication_links_by_component[flow.source][f"Flow {index}"] = {
                    "target": flow.target,
                    "description": flow.description or f"{flow.source} to {flow.target}",
                    "protocol": PROTOCOL_MAP.get(flow.protocol, "unknown-protocol"),
                    "authentication": _infer_authentication(flow),
                    "authorization": _infer_authorization(flow),
                    "tags": [],
                    "vpn": False,
                    "ip_filtered": False,
                    "readonly": _is_readonly_flow(flow),
                    "usage": "business",
                    "data_assets_sent": [data_asset_id],
                    "data_assets_received": [],
                }

    technical_assets: dict[str, dict] = {}
    for alias, component in sorted_components:
        technical_assets[_unique_label(component.name, alias, technical_assets)] = {
            "id": alias,
            "description": f"Imported from UML element '{component.name}' of kind '{component.kind}'.",
            "type": TECHNICAL_ASSET_TYPE_MAP.get(component.kind, "process"),
            "usage": "business",
            "used_as_client_by_human": component.kind == "actor" or "human-user" in component.tags,
            "out_of_scope": False,
            "justification_out_of_scope": "",
            "size": TECHNICAL_ASSET_SIZE_MAP.get(component.kind, "component"),
            "technology": TECHNOLOGY_MAP.get(component.kind, "unknown-technology"),
            "tags": component.tags,
            "internet": _is_internet_exposed(component),
            "machine": "physical" if component.kind in {"actor", "device"} else "virtual",
            "encryption": "transparent" if component.kind in STORAGE_KINDS else "none",
            "owner": "Imported from UML",
            "confidentiality": "restricted",
            "integrity": "important",
            "availability": "important",
            "justification_cia_rating": (
                "This asset was inferred automatically from the UML model and needs manual CIA review."
            ),
            "multi_tenant": False,
            "redundant": False,
            "custom_developed_parts": component.kind in {"component", "service", "system", "node", "cloud"},
            "data_assets_processed": sorted(processed_assets_by_component[alias]),
            "data_assets_stored": sorted(stored_assets_by_component[alias]),
            "data_formats_accepted": [],
            "communication_links": communication_links_by_component[alias],
        }

    trust_boundaries: dict[str, dict] = {}
    for boundary_name in sorted(model.boundaries):
        direct_assets = [
            alias
            for alias, component in sorted_components
            if component.boundaries and component.boundaries[-1] == boundary_name
        ]
        trust_boundaries[_unique_label(boundary_name, boundary_ids[boundary_name], trust_boundaries)] = {
            "id": boundary_ids[boundary_name],
            "description": boundary_name,
            "type": _infer_trust_boundary_type(boundary_name),
            "tags": [],
            "technical_assets_inside": direct_assets,
            "trust_boundaries_nested": [boundary_ids[name] for name in sorted(boundary_children[boundary_name])],
        }

    data_assets: dict[str, dict] = {}
    for inferred_asset in inferred_data_assets:
        label = _unique_label(inferred_asset["label"], inferred_asset["asset"]["id"], data_assets)
        data_assets[label] = inferred_asset["asset"]

    return {
        "threagile_version": "1.0.0",
        "title": model.title,
        "date": date.today().isoformat(),
        "author": {
            "name": "threatmod-automation",
            "homepage": "",
        },
        "management_summary_comment": "Imported automatically from UML / PlantUML by threatmod-automation.",
        "business_criticality": "important",
        "business_overview": {
            "description": "Review and refine the inferred business context before relying on generated findings.",
            "images": [],
        },
        "technical_overview": {
            "description": "This Threagile model was generated from the parsed architecture and should be refined in-place.",
            "images": [],
        },
        "questions": {
            "Which assets process safety-relevant or mission-critical functions?": "",
            "Which flows require authentication, encryption, freshness, and anti-replay controls?": "",
            "Where are identities, secrets, and update channels administered?": "",
        },
        "abuse_cases": {},
        "security_requirements": {},
        "tags_available": sorted({tag for component in model.components.values() for tag in component.tags}),
        "data_assets": data_assets,
        "technical_assets": technical_assets,
        "trust_boundaries": trust_boundaries,
        "shared_runtimes": {},
        "individual_risk_categories": {},
        "risk_tracking": {},
    }


def generate_threagile_pdf(
    model_path: Path,
    *,
    docker_image: str = DEFAULT_THREAGILE_IMAGE,
) -> Path:
    if not docker_image.strip():
        raise RuntimeError("A Threagile Docker image name is required when Docker report generation is enabled.")
    if shutil.which("docker") is None:
        raise RuntimeError(
            "Docker is not installed or not available on PATH. Install Docker to generate the Threagile PDF report."
        )

    model_path = model_path.resolve()
    if not model_path.exists():
        raise RuntimeError(f"The generated Threagile model file does not exist: {model_path}")

    output_dir = model_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    started_at = time.time()
    container_model_path = THREAGILE_WORKDIR / model_path.name

    command = [
        "docker",
        "run",
        "--rm",
    ]
    if hasattr(os, "getuid") and hasattr(os, "getgid"):
        command.extend(["--user", f"{os.getuid()}:{os.getgid()}"])
    command.extend(
        [
            "-v",
            f"{output_dir}:{THREAGILE_WORKDIR}",
            docker_image.strip(),
            "--model",
            str(container_model_path),
            "--output",
            str(THREAGILE_WORKDIR),
        ]
    )

    try:
        subprocess.run(command, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as exc:
        details = "\n".join(part for part in [exc.stdout.strip(), exc.stderr.strip()] if part)
        message = (
            f"Threagile Docker execution failed using image '{docker_image.strip()}'. "
            f"Host model: {model_path}. Container model: {container_model_path}."
        )
        if details:
            message = f"{message}\n{details}"
        raise RuntimeError(message) from exc

    pdf_path = _find_generated_pdf(output_dir, started_at)
    if pdf_path is None:
        raise RuntimeError(
            "Threagile finished without a detectable PDF report in the output directory. "
            "Check the generated Docker artifacts and the model compatibility."
        )
    return pdf_path


def _build_data_assets(model: ArchitectureModel) -> list[dict]:
    data_assets: list[dict] = []

    for index, flow in enumerate(model.data_flows, start=1):
        source_name = model.components.get(flow.source).name if flow.source in model.components else flow.source
        target_name = model.components.get(flow.target).name if flow.target in model.components else flow.target
        label = flow.description.strip() or f"{source_name} to {target_name} payload"
        data_assets.append(
            {
                "label": label,
                "flow": flow,
                "asset": {
                    "id": f"flow-data-{index}",
                    "description": f"Inferred from the data flow between {source_name} and {target_name}.",
                    "usage": "business",
                    "tags": [],
                    "origin": source_name,
                    "owner": target_name,
                    "quantity": "many",
                    "confidentiality": "restricted",
                    "integrity": "important",
                    "availability": "important",
                    "justification_cia_rating": (
                        "This data asset was inferred automatically from a UML flow and needs manual refinement."
                    ),
                },
            }
        )

    if data_assets:
        return data_assets

    return [
        {
            "label": "Architecture data",
            "flow": None,
            "asset": {
                "id": "architecture-data",
                "description": "Fallback data asset inferred from the imported architecture.",
                "usage": "business",
                "tags": [],
                "origin": "Imported UML",
                "owner": "Imported UML",
                "quantity": "few",
                "confidentiality": "restricted",
                "integrity": "important",
                "availability": "important",
                "justification_cia_rating": (
                    "The architecture contains technical assets but no explicit data flows yet."
                ),
            },
        }
    ]


def _find_generated_pdf(output_dir: Path, started_at: float) -> Path | None:
    candidates = sorted(output_dir.glob("*.pdf"), key=lambda path: path.stat().st_mtime, reverse=True)
    if not candidates:
        return None

    recent = [candidate for candidate in candidates if candidate.stat().st_mtime >= started_at - 1]

    for candidate in recent:
        if "report" in candidate.name.lower():
            return candidate

    if recent:
        return recent[0]

    for candidate in candidates:
        if "report" in candidate.name.lower():
            return candidate
    return candidates[0]


def _infer_trust_boundary_type(boundary_name: str) -> str:
    lower_name = boundary_name.lower()
    if "cloud" in lower_name:
        return "network-cloud-provider"
    if any(token in lower_name for token in ("runtime", "cluster", "namespace", "container")):
        return "execution-environment"
    if any(token in lower_name for token in ("dmz", "segment", "zone", "network", "lan", "vlan")):
        return "network-on-prem"
    return "network-on-prem"


def _infer_authentication(flow) -> str:
    text = f"{flow.description} {flow.protocol}".lower()
    if any(token in text for token in ("token", "jwt", "oauth", "bearer")):
        return "token"
    if any(token in text for token in ("session", "cookie")):
        return "session-id"
    if any(token in text for token in ("cert", "certificate", "mtls")):
        return "client-certificate"
    if any(token in text for token in ("login", "credential", "password", "user")):
        return "credentials"
    return "none"


def _infer_authorization(flow) -> str:
    text = f"{flow.description} {flow.protocol}".lower()
    if any(token in text for token in ("user", "operator", "admin", "identity")):
        return "enduser-identity-propagation"
    if any(token in text for token in ("service", "backend", "api", "agent")):
        return "technical-user"
    return "none"


def _is_readonly_flow(flow) -> bool:
    text = flow.description.lower()
    return any(token in text for token in ("read", "query", "fetch", "pull", "subscribe"))


def _is_internet_exposed(component) -> bool:
    boundary_text = " ".join(component.boundaries).lower()
    haystack = f"{component.name} {component.kind} {' '.join(component.tags)} {boundary_text}".lower()
    return any(token in haystack for token in ("cloud", "internet", "external", "mobile", "remote"))


def _slugify(value: str) -> str:
    cleaned = [
        char.lower() if char.isalnum() else "-"
        for char in value.strip()
    ]
    slug = "".join(cleaned).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or "boundary"


def _unique_label(preferred: str, fallback: str, container: dict[str, dict]) -> str:
    label = preferred.strip() or fallback
    if label not in container:
        return label

    counter = 2
    while True:
        candidate = f"{label} ({counter})"
        if candidate not in container:
            return candidate
        counter += 1
