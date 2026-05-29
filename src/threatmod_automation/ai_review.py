from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from typing import Any
from urllib import error, request

from .models import ArchitectureModel, Component, DataFlow


SUPPORTED_COMPONENT_KINDS = {
    "actor",
    "component",
    "database",
    "queue",
    "node",
    "cloud",
    "system",
    "device",
    "service",
}

PROTOCOL_ALIASES = {
    "http": "http",
    "https": "https",
    "tls": "tls",
    "mtls": "tls",
    "mqtt": "mqtt",
    "can": "can",
    "can bus": "can",
    "ethernet": "ethernet",
    "udp": "udp",
    "tcp": "tcp",
    "ssh": "ssh",
    "opcua": "opcua",
    "opc ua": "opcua",
}


@dataclass(slots=True)
class AIArchitectureDraft:
    enabled: bool
    provider: str
    model: str
    summary: str
    assumptions: list[str]
    architecture: ArchitectureModel
    raw_text: str = ""


@dataclass(slots=True)
class AIReviewResult:
    enabled: bool
    provider: str
    model: str
    summary: str
    current_status: list[str]
    possible_missing_components: list[str]
    possible_missing_connections: list[str]
    impacts_to_investigate: list[str]
    suggested_countermeasures: list[str]
    raw_text: str = ""


def draft_architecture_with_openai(
    parsed_model: ArchitectureModel,
    *,
    source_text: str = "",
    source_name: str | None = None,
    architecture_notes: str | None = None,
    api_key: str | None = None,
    model_name: str = "gpt-5.2",
    timeout_seconds: int = 60,
) -> AIArchitectureDraft:
    resolved_api_key = api_key or os.environ.get("OPENAI_API_KEY")
    if not resolved_api_key:
        raise RuntimeError("OPENAI_API_KEY is not set. Export it or pass an API key before using AI architecture drafting.")

    payload = {
        "model": model_name,
        "reasoning": {"effort": "medium"},
        "instructions": (
            "You are creating a normalized system architecture for threat modelling. "
            "Return only JSON matching the requested schema. Do not write YAML. "
            "Use stable lower_snake_case aliases, preserve known architecture facts, "
            "and add implied assets only when they are useful for ISO 21434 or IEC 62443 review. "
            "Make uncertainty explicit in assumptions instead of inventing details."
        ),
        "text": {
            "format": {
                "type": "json_schema",
                "name": "architecture_draft",
                "strict": True,
                "schema": _architecture_draft_schema(),
            }
        },
        "input": _build_architecture_draft_prompt(
            parsed_model,
            source_text=source_text,
            source_name=source_name,
            architecture_notes=architecture_notes,
        ),
    }
    body = json.dumps(payload).encode("utf-8")
    http_request = request.Request(
        "https://api.openai.com/v1/responses",
        data=body,
        headers={
            "Authorization": f"Bearer {resolved_api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with request.urlopen(http_request, timeout=timeout_seconds) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAI architecture draft failed with HTTP {exc.code}: {details}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"OpenAI architecture draft failed: {exc.reason}") from exc

    output_text = _extract_output_text(response_payload).strip()
    if not output_text:
        status = response_payload.get("status", "unknown")
        raise RuntimeError(
            "OpenAI architecture draft did not include any readable model text. "
            f"Response status: {status}. "
            f"Available top-level keys: {sorted(response_payload.keys())}."
        )

    draft_data = _load_json_object(output_text, "OpenAI architecture draft")
    return AIArchitectureDraft(
        enabled=True,
        provider="OpenAI",
        model=model_name,
        summary=_string_value(draft_data.get("summary")),
        assumptions=_as_string_list(draft_data.get("assumptions")),
        architecture=_architecture_model_from_payload(draft_data, fallback_title=parsed_model.title),
        raw_text=output_text,
    )


def draft_architecture_with_copilot(
    parsed_model: ArchitectureModel,
    *,
    source_text: str = "",
    source_name: str | None = None,
    architecture_notes: str | None = None,
    api_key: str | None = None,
    model_name: str = "openai/gpt-5.2",
    timeout_seconds: int = 60,
) -> AIArchitectureDraft:
    resolved_api_key = api_key or os.environ.get("GITHUB_MODELS_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not resolved_api_key:
        raise RuntimeError(
            "GITHUB_MODELS_TOKEN or GITHUB_TOKEN is not set. Export one before using AI architecture drafting."
        )

    payload = {
        "model": model_name,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are creating a normalized system architecture for threat modelling. "
                    "Return valid JSON only. Do not write YAML. "
                    "Use stable lower_snake_case aliases, preserve known architecture facts, "
                    "and make uncertainty explicit in assumptions."
                ),
            },
            {
                "role": "user",
                "content": _build_architecture_draft_prompt(
                    parsed_model,
                    source_text=source_text,
                    source_name=source_name,
                    architecture_notes=architecture_notes,
                ),
            },
        ],
        "temperature": 0.2,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "architecture_draft",
                "schema": _architecture_draft_schema(),
            },
        },
    }
    body = json.dumps(payload).encode("utf-8")
    http_request = request.Request(
        "https://models.github.ai/inference/chat/completions",
        data=body,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {resolved_api_key}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2026-03-10",
        },
        method="POST",
    )

    try:
        with request.urlopen(http_request, timeout=timeout_seconds) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub Models architecture draft failed with HTTP {exc.code}: {details}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"GitHub Models architecture draft failed: {exc.reason}") from exc

    output_text = _extract_github_models_text(response_payload).strip()
    if not output_text:
        raise RuntimeError(
            "GitHub Models architecture draft did not include any readable model text. "
            f"Available top-level keys: {sorted(response_payload.keys())}."
        )

    draft_data = _load_json_object(output_text, "GitHub Models architecture draft")
    return AIArchitectureDraft(
        enabled=True,
        provider="GitHub Copilot",
        model=model_name,
        summary=_string_value(draft_data.get("summary")),
        assumptions=_as_string_list(draft_data.get("assumptions")),
        architecture=_architecture_model_from_payload(draft_data, fallback_title=parsed_model.title),
        raw_text=output_text,
    )


def review_architecture_with_openai(
    model: ArchitectureModel,
    *,
    api_key: str | None = None,
    model_name: str = "gpt-5.2",
    timeout_seconds: int = 60,
) -> AIReviewResult:
    resolved_api_key = api_key or os.environ.get("OPENAI_API_KEY")
    if not resolved_api_key:
        raise RuntimeError("OPENAI_API_KEY is not set. Export it or pass an API key before using --ai-review.")

    payload = {
        "model": model_name,
        "reasoning": {"effort": "medium"},
        "instructions": (
            "You are reviewing a parsed system architecture for threat modelling. "
            "Focus on current status, possible missing components, possible missing connections, "
            "likely impacts, and possible countermeasures using ISO 21434 and IEC 62443 as the main lens. "
            "Be specific, architecture-focused, and cautious about uncertainty."
        ),
        "text": {
            "format": {
                "type": "json_schema",
                "name": "architecture_review",
                "strict": True,
                "schema": _review_schema(),
            }
        },
        "input": _build_prompt(model),
    }
    body = json.dumps(payload).encode("utf-8")
    http_request = request.Request(
        "https://api.openai.com/v1/responses",
        data=body,
        headers={
            "Authorization": f"Bearer {resolved_api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with request.urlopen(http_request, timeout=timeout_seconds) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAI API request failed with HTTP {exc.code}: {details}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"OpenAI API request failed: {exc.reason}") from exc

    output_text = _extract_output_text(response_payload).strip()
    if not output_text:
        status = response_payload.get("status", "unknown")
        raise RuntimeError(
            "OpenAI API response did not include any readable model text. "
            f"Response status: {status}. "
            f"Available top-level keys: {sorted(response_payload.keys())}."
        )

    review_data = json.loads(output_text)
    return AIReviewResult(
        enabled=True,
        provider="OpenAI",
        model=model_name,
        summary=review_data.get("summary", "").strip(),
        current_status=_as_string_list(review_data.get("current_status")),
        possible_missing_components=_as_string_list(review_data.get("possible_missing_components")),
        possible_missing_connections=_as_string_list(review_data.get("possible_missing_connections")),
        impacts_to_investigate=_as_string_list(review_data.get("impacts_to_investigate")),
        suggested_countermeasures=_as_string_list(review_data.get("suggested_countermeasures")),
        raw_text=output_text,
    )


def review_architecture_with_copilot(
    model: ArchitectureModel,
    *,
    api_key: str | None = None,
    model_name: str = "openai/gpt-5.2",
    timeout_seconds: int = 60,
) -> AIReviewResult:
    resolved_api_key = api_key or os.environ.get("GITHUB_MODELS_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not resolved_api_key:
        raise RuntimeError(
            "GITHUB_MODELS_TOKEN or GITHUB_TOKEN is not set. Export one before using --copilot-review."
        )

    payload = {
        "model": model_name,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are reviewing a parsed system architecture for threat modelling. "
                    "Focus on current status, possible missing components, possible missing connections, "
                    "likely impacts, and possible countermeasures using ISO 21434 and IEC 62443 as the main lens. "
                    "Return valid JSON only."
                ),
            },
            {
                "role": "user",
                "content": _build_prompt(model),
            },
        ],
        "temperature": 0.2,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "architecture_review",
                "schema": _review_schema(),
            },
        },
    }
    body = json.dumps(payload).encode("utf-8")
    http_request = request.Request(
        "https://models.github.ai/inference/chat/completions",
        data=body,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {resolved_api_key}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2026-03-10",
        },
        method="POST",
    )

    try:
        with request.urlopen(http_request, timeout=timeout_seconds) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub Models request failed with HTTP {exc.code}: {details}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"GitHub Models request failed: {exc.reason}") from exc

    output_text = _extract_github_models_text(response_payload).strip()
    if not output_text:
        raise RuntimeError(
            "GitHub Models response did not include any readable model text. "
            f"Available top-level keys: {sorted(response_payload.keys())}."
        )

    review_data = json.loads(output_text)
    return AIReviewResult(
        enabled=True,
        provider="GitHub Copilot",
        model=model_name,
        summary=review_data.get("summary", "").strip(),
        current_status=_as_string_list(review_data.get("current_status")),
        possible_missing_components=_as_string_list(review_data.get("possible_missing_components")),
        possible_missing_connections=_as_string_list(review_data.get("possible_missing_connections")),
        impacts_to_investigate=_as_string_list(review_data.get("impacts_to_investigate")),
        suggested_countermeasures=_as_string_list(review_data.get("suggested_countermeasures")),
        raw_text=output_text,
    )


def review_result_to_dict(result: AIReviewResult) -> dict[str, Any]:
    return asdict(result)


def architecture_draft_to_dict(result: AIArchitectureDraft) -> dict[str, Any]:
    return {
        "enabled": result.enabled,
        "provider": result.provider,
        "model": result.model,
        "summary": result.summary,
        "assumptions": result.assumptions,
        "architecture": _architecture_model_to_dict(result.architecture),
        "raw_text": result.raw_text,
    }


def _build_prompt(model: ArchitectureModel) -> str:
    architecture = {
        "title": model.title,
        "trust_boundaries": sorted(model.boundaries),
        "components": [
            {
                "alias": component.alias,
                "name": component.name,
                "kind": component.kind,
                "boundaries": component.boundaries,
                "tags": component.tags,
            }
            for component in model.components.values()
        ],
        "data_flows": [
            {
                "source": flow.source,
                "target": flow.target,
                "description": flow.description,
                "protocol": flow.protocol,
            }
            for flow in model.data_flows
        ],
    }

    return (
        "Review this parsed architecture before final threat-model generation.\n"
        "Return the requested structured fields for automation.\n"
        f"Architecture:\n{json.dumps(architecture, indent=2)}\n"
    )


def _build_architecture_draft_prompt(
    parsed_model: ArchitectureModel,
    *,
    source_text: str = "",
    source_name: str | None = None,
    architecture_notes: str | None = None,
) -> str:
    prompt_sections = [
        "Create a clean architecture draft that the application can convert into a Threagile YAML template.",
        "Return components, trust boundaries, and data flows only as JSON.",
        "Allowed component kinds: actor, component, database, queue, node, cloud, system, device, service.",
        "Prefer concrete architecture elements over generic placeholders.",
        "Every data flow endpoint should match a component alias.",
        "",
        "Parsed architecture context:",
        json.dumps(_architecture_model_to_dict(parsed_model), indent=2),
    ]
    if source_name:
        prompt_sections.extend(["", f"Source name: {source_name}"])
    if source_text.strip():
        prompt_sections.extend(["", "Original architecture source:", source_text.strip()])
    if architecture_notes and architecture_notes.strip():
        prompt_sections.extend(["", "Additional architecture notes:", architecture_notes.strip()])
    return "\n".join(prompt_sections)


def _architecture_model_to_dict(model: ArchitectureModel) -> dict[str, Any]:
    return {
        "title": model.title,
        "trust_boundaries": sorted(model.boundaries),
        "components": [
            {
                "alias": component.alias,
                "name": component.name,
                "kind": component.kind,
                "boundaries": component.boundaries,
                "tags": component.tags,
            }
            for component in model.components.values()
        ],
        "data_flows": [
            {
                "source": flow.source,
                "target": flow.target,
                "description": flow.description,
                "protocol": flow.protocol,
            }
            for flow in model.data_flows
        ],
    }


def _architecture_model_from_payload(payload: dict[str, Any], *, fallback_title: str) -> ArchitectureModel:
    title = _string_value(payload.get("title")) or fallback_title or "AI Generated Threat Model"
    model = ArchitectureModel(title=title)
    alias_lookup: dict[str, str] = {}

    for raw_component in _object_list(payload.get("components")):
        name = _string_value(raw_component.get("name")) or "Unnamed component"
        raw_alias = _string_value(raw_component.get("alias")) or name
        alias = _next_available_alias(model.components, _alias_candidate(raw_alias))
        kind = _normalize_component_kind(raw_component.get("kind"))
        boundaries = _as_string_list(raw_component.get("boundaries"))
        tags = sorted(set(_as_string_list(raw_component.get("tags")) or _infer_tags(name, kind)))

        model.components[alias] = Component(
            alias=alias,
            name=name,
            kind=kind,
            boundaries=boundaries,
            tags=tags,
        )
        model.boundaries.update(boundaries)
        alias_lookup[raw_alias] = alias
        alias_lookup[_alias_candidate(raw_alias)] = alias
        alias_lookup[name] = alias
        alias_lookup[_alias_candidate(name)] = alias

    model.boundaries.update(_as_string_list(payload.get("trust_boundaries")))

    for raw_flow in _object_list(payload.get("data_flows")):
        source = _resolve_endpoint(raw_flow.get("source"), alias_lookup, model)
        target = _resolve_endpoint(raw_flow.get("target"), alias_lookup, model)
        description = _string_value(raw_flow.get("description"))
        protocol = _normalize_protocol(raw_flow.get("protocol"), description)
        if source and target and source != target:
            model.data_flows.append(
                DataFlow(
                    source=source,
                    target=target,
                    direction="-->",
                    description=description,
                    protocol=protocol,
                )
            )

    return model


def _architecture_draft_schema() -> dict[str, Any]:
    string_array = {
        "type": "array",
        "items": {"type": "string"},
    }
    component = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "alias": {"type": "string"},
            "name": {"type": "string"},
            "kind": {
                "type": "string",
                "enum": sorted(SUPPORTED_COMPONENT_KINDS),
            },
            "boundaries": string_array,
            "tags": string_array,
        },
        "required": ["alias", "name", "kind", "boundaries", "tags"],
    }
    data_flow = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "source": {"type": "string"},
            "target": {"type": "string"},
            "description": {"type": "string"},
            "protocol": {"type": "string"},
        },
        "required": ["source", "target", "description", "protocol"],
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "title": {"type": "string"},
            "summary": {"type": "string"},
            "assumptions": string_array,
            "trust_boundaries": string_array,
            "components": {
                "type": "array",
                "items": component,
            },
            "data_flows": {
                "type": "array",
                "items": data_flow,
            },
        },
        "required": [
            "title",
            "summary",
            "assumptions",
            "trust_boundaries",
            "components",
            "data_flows",
        ],
    }


def _as_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _object_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_value(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _load_json_object(text: str, source: str) -> dict[str, Any]:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{source} did not return valid JSON: {exc.msg}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{source} must return a JSON object.")
    return parsed


def _normalize_component_kind(value: Any) -> str:
    kind = _string_value(value).lower()
    if kind in SUPPORTED_COMPONENT_KINDS:
        return kind
    return "component"


def _normalize_protocol(value: Any, description: str) -> str:
    protocol = _string_value(value).lower()
    if protocol and protocol != "unknown":
        if protocol in PROTOCOL_ALIASES:
            return PROTOCOL_ALIASES[protocol]
        for hint, normalized in sorted(PROTOCOL_ALIASES.items(), key=lambda item: len(item[0]), reverse=True):
            if hint in protocol:
                return normalized
        return protocol

    description_text = description.lower()
    for hint, normalized in sorted(PROTOCOL_ALIASES.items(), key=lambda item: len(item[0]), reverse=True):
        if hint in description_text:
            return normalized
    return "unknown"


def _resolve_endpoint(value: Any, alias_lookup: dict[str, str], model: ArchitectureModel) -> str:
    raw_endpoint = _string_value(value)
    if not raw_endpoint:
        return ""
    if raw_endpoint in alias_lookup:
        return alias_lookup[raw_endpoint]

    candidate = _alias_candidate(raw_endpoint)
    if candidate in alias_lookup:
        return alias_lookup[candidate]
    if candidate in model.components:
        return candidate

    alias = _next_available_alias(model.components, candidate)
    model.components[alias] = Component(
        alias=alias,
        name=raw_endpoint,
        kind="component",
        boundaries=[],
        tags=["needs-review"],
    )
    alias_lookup[raw_endpoint] = alias
    alias_lookup[candidate] = alias
    return alias


def _alias_candidate(value: str) -> str:
    chars = [char.lower() if char.isalnum() else "_" for char in value.strip()]
    alias = "".join(chars).strip("_")
    while "__" in alias:
        alias = alias.replace("__", "_")
    return alias or "component"


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
    if any(token in tokens for token in ("db", "database", "storage", "vault", "historian")):
        tags.add("data-store")
    if any(token in tokens for token in ("user", "operator", "driver", "admin", "maintainer")):
        tags.add("human-user")
    if any(token in tokens for token in ("cloud", "backend", "api", "service")):
        tags.add("it-service")
    return sorted(tags)


def _extract_output_text(response_payload: dict[str, Any]) -> str:
    sdk_output_text = response_payload.get("output_text")
    if isinstance(sdk_output_text, str) and sdk_output_text.strip():
        return sdk_output_text

    collected_text: list[str] = []
    refusals: list[str] = []

    for item in response_payload.get("output", []):
        if not isinstance(item, dict):
            continue
        if item.get("type") != "message":
            continue

        for content in item.get("content", []):
            if not isinstance(content, dict):
                continue

            content_type = content.get("type")
            if content_type in {"output_text", "text"}:
                text = content.get("text")
                if isinstance(text, str) and text.strip():
                    collected_text.append(text)
            elif content_type == "refusal":
                refusal_text = content.get("refusal") or content.get("text")
                if isinstance(refusal_text, str) and refusal_text.strip():
                    refusals.append(refusal_text)

    if collected_text:
        return "\n".join(collected_text)
    if refusals:
        raise RuntimeError("OpenAI model refused the request: " + " ".join(refusals))
    return ""


def _extract_github_models_text(response_payload: dict[str, Any]) -> str:
    choices = response_payload.get("choices", [])
    if not isinstance(choices, list):
        return ""

    collected_text: list[str] = []
    for choice in choices:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message", {})
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            collected_text.append(content)

    return "\n".join(collected_text)


def _review_schema() -> dict[str, Any]:
    string_array = {
        "type": "array",
        "items": {"type": "string"},
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "summary": {"type": "string"},
            "current_status": string_array,
            "possible_missing_components": string_array,
            "possible_missing_connections": string_array,
            "impacts_to_investigate": string_array,
            "suggested_countermeasures": string_array,
        },
        "required": [
            "summary",
            "current_status",
            "possible_missing_components",
            "possible_missing_connections",
            "impacts_to_investigate",
            "suggested_countermeasures",
        ],
    }
