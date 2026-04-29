from __future__ import annotations

from .ai_review import AIReviewResult, review_result_to_dict
from .models import ArchitectureModel, Component


def build_assessment(
    model: ArchitectureModel,
    ai_review: AIReviewResult | None = None,
    ai_reviews: list[AIReviewResult] | None = None,
) -> dict:
    coverage = _coverage_snapshot(model)
    gaps = _find_gaps(coverage)
    assessment = {
        "summary": {
            "title": model.title,
            "components": len(model.components),
            "data_flows": len(model.data_flows),
            "trust_boundaries": len(model.boundaries),
        },
        "coverage": coverage,
        "missing_or_needs_review": gaps,
        "standards_guidance": {
            "iso_21434": _iso_21434_guidance(coverage),
            "iec_62443": _iec_62443_guidance(coverage),
        },
    }
    resolved_reviews = list(ai_reviews or [])
    if ai_review is not None:
        resolved_reviews.append(ai_review)
    if resolved_reviews:
        assessment["ai_reviews"] = [review_result_to_dict(item) for item in resolved_reviews]
    return assessment


def render_assessment_markdown(assessment: dict) -> str:
    summary = assessment["summary"]
    lines = [
        f"# {summary['title']}",
        "",
        "## Coverage Summary",
        f"- Components discovered: {summary['components']}",
        f"- Data flows discovered: {summary['data_flows']}",
        f"- Trust boundaries discovered: {summary['trust_boundaries']}",
        "",
        "## Missing Or Needs Review",
    ]

    for item in assessment["missing_or_needs_review"]:
        lines.append(f"- {item}")

    lines.extend(["", "## ISO 21434 Focus"])
    for item in assessment["standards_guidance"]["iso_21434"]:
        lines.append(f"- {item}")

    lines.extend(["", "## IEC 62443 Focus"])
    for item in assessment["standards_guidance"]["iec_62443"]:
        lines.append(f"- {item}")

    ai_reviews = assessment.get("ai_reviews", [])
    if ai_reviews:
        lines.extend(["", "## AI Reviews"])
        for ai_review in ai_reviews:
            lines.extend(["", f"### {ai_review['provider']}", f"Model: `{ai_review['model']}`", ""])
            if ai_review["summary"]:
                lines.append(ai_review["summary"])
                lines.append("")
            _append_list_section(lines, "Current Status", ai_review["current_status"], level=4)
            _append_list_section(lines, "Possible Missing Components", ai_review["possible_missing_components"], level=4)
            _append_list_section(lines, "Possible Missing Connections", ai_review["possible_missing_connections"], level=4)
            _append_list_section(lines, "Impacts To Investigate", ai_review["impacts_to_investigate"], level=4)
            _append_list_section(lines, "Suggested Countermeasures", ai_review["suggested_countermeasures"], level=4)

    return "\n".join(lines) + "\n"


def _append_list_section(lines: list[str], title: str, items: list[str], *, level: int = 2) -> None:
    lines.extend([f"{'#' * level} {title}"])
    if items:
        for item in items:
            lines.append(f"- {item}")
    else:
        lines.append("- No additional items were returned.")
    lines.append("")


def _coverage_snapshot(model: ArchitectureModel) -> dict[str, bool | int]:
    components = list(model.components.values())
    flow_text = " ".join(f"{flow.description} {flow.protocol}" for flow in model.data_flows).lower()
    return {
        "has_external_actor": any(_is_external_actor(component) for component in components),
        "has_service_or_process": any(component.kind in {"component", "service", "system", "node"} for component in components),
        "has_data_store": any(component.kind == "database" or "data-store" in component.tags for component in components),
        "has_network_boundary": bool(model.boundaries),
        "has_data_flow": bool(model.data_flows),
        "has_ot_asset": any("operational-technology" in component.tags for component in components),
        "has_identity_or_user": any("human-user" in component.tags or component.kind == "actor" for component in components),
        "has_monitoring_component": any(_contains(component, ("siem", "log", "monitor", "ids", "alert")) for component in components),
        "has_update_path": any(_contains(component, ("ota", "update", "deploy", "firmware", "maintenance")) for component in components)
        or any(token in flow_text for token in ("ota", "update", "deploy", "firmware", "maintenance", "diagnostic")),
        "has_security_boundary_component": any(_contains(component, ("gateway", "firewall", "vpn", "proxy")) for component in components),
        "has_safety_relevant_asset": any(_contains(component, ("brake", "steering", "engine", "powertrain", "plc", "safety")) for component in components),
        "component_count": len(components),
    }


def _find_gaps(coverage: dict[str, bool | int]) -> list[str]:
    findings: list[str] = []
    if not coverage["has_service_or_process"]:
        findings.append("No internal service or processing component was identified.")
    if not coverage["has_data_flow"]:
        findings.append("No data flow was identified, so trust boundaries and protocol exposure cannot yet be assessed.")
    if not coverage["has_data_store"]:
        findings.append("No data store was identified. Confirm whether telemetry, credentials, configurations, or logs are persisted anywhere.")
    if not coverage["has_external_actor"]:
        findings.append("No external actor or upstream/downstream system is modelled. Check user, maintainer, supplier, and remote backend interactions.")
    if not coverage["has_network_boundary"]:
        findings.append("No trust boundary or network zone was identified. Add packages/zones for ECU, plant, DMZ, cloud, and maintenance segments.")
    if not coverage["has_security_boundary_component"]:
        findings.append("No gateway, firewall, proxy, or comparable choke point was identified.")
    if not coverage["has_monitoring_component"]:
        findings.append("No monitoring, logging, IDS, or alerting component was identified.")
    if not coverage["has_update_path"]:
        findings.append("No firmware/software update or maintenance path was identified.")
    return findings or ["Core architecture elements were detected. Review protocol, authentication, and asset criticality details next."]


def _iso_21434_guidance(coverage: dict[str, bool | int]) -> list[str]:
    guidance = [
        "Confirm every vehicle, ECU, gateway, sensor, actuator, backend, and maintenance interface is modelled as an asset or interface.",
        "Mark safety-relevant and cybersecurity-relevant assets, then review each flow for attack feasibility, impact, and damage scenario inputs.",
        "Check authenticity, integrity, freshness, and authorization controls for diagnostic, update, and control channels.",
        "Document where credentials, keys, certificates, and calibration/configuration data are stored and rotated.",
    ]
    if not coverage["has_ot_asset"]:
        guidance.append("No obvious vehicle or OT asset was inferred. If this is automotive, add ECUs, in-vehicle networks, diagnostics, and telematics elements explicitly.")
    if not coverage["has_safety_relevant_asset"]:
        guidance.append("No safety-relevant function was inferred. Identify whether braking, steering, propulsion, or safety controllers are in scope.")
    return guidance


def _iec_62443_guidance(coverage: dict[str, bool | int]) -> list[str]:
    guidance = [
        "Partition the model into zones and conduits, then verify every conduit has an explicit protocol, authentication expectation, and trust decision.",
        "Identify industrial control assets such as PLCs, HMIs, engineering workstations, historians, and remote access paths.",
        "Check account management, least privilege, session control, logging, backup, recovery, and patch/update workflows for each zone.",
        "Review boundary protections such as firewalls, jump hosts, data diodes, or secure gateways between enterprise, DMZ, and control networks.",
    ]
    if not coverage["has_network_boundary"]:
        guidance.append("No zones were inferred. IEC 62443 analysis will stay shallow until network segmentation is described in the UML.")
    if not coverage["has_identity_or_user"]:
        guidance.append("No operator, maintainer, or service account actor was identified. Add human and machine identities per zone.")
    return guidance


def _is_external_actor(component: Component) -> bool:
    if component.kind == "actor":
        return True
    return _contains(component, ("external", "supplier", "cloud", "mobile", "backend"))


def _contains(component: Component, tokens: tuple[str, ...]) -> bool:
    haystack = f"{component.name} {component.kind} {' '.join(component.tags)}".lower()
    return any(token in haystack for token in tokens)
