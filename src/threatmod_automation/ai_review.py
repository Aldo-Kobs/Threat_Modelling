from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from typing import Any
from urllib import error, request

from .models import ArchitectureModel


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


def _as_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


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
        raise RuntimeError("OpenAI model refused the AI review request: " + " ".join(refusals))
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
