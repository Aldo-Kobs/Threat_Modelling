from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ai_review import (
    AIArchitectureDraft,
    AIReviewResult,
    _architecture_model_from_payload,
    architecture_draft_to_dict,
    draft_architecture_with_copilot,
    draft_architecture_with_openai,
    review_architecture_with_copilot,
    review_architecture_with_openai,
)
from .guidance import build_assessment, render_assessment_markdown
from .models import ArchitectureModel
from .parser import parse_architecture
from .threagile import (
    DEFAULT_THREAGILE_IMAGE,
    EXCEL_SHEET_NAME_LIMIT,
    build_threagile_yaml_model,
    generate_threagile_pdf,
)
from .yaml_writer import dump_yaml


@dataclass(slots=True)
class RunResult:
    yaml_path: Path
    report_path: Path
    threagile_pdf_path: Path | None
    ai_review_path: Path | None
    ai_reviews: list[AIReviewResult]
    ai_architecture_path: Path | None = None
    ai_architecture_draft: AIArchitectureDraft | None = None


def run_analysis(
    input_path: Path | None,
    *,
    output_dir: Path,
    yaml_input_path: Path | None = None,
    architecture_notes: str | None = None,
    ai_architecture: bool = False,
    ai_architecture_provider: str = "openai",
    ai_architecture_model: str | None = None,
    openai_review: bool = False,
    openai_model: str = "gpt-5.2",
    openai_api_key: str | None = None,
    copilot_review: bool = False,
    copilot_model: str = "openai/gpt-5.2",
    copilot_api_key: str | None = None,
    threagile_docker: bool = False,
    threagile_image: str = DEFAULT_THREAGILE_IMAGE,
) -> RunResult:
    if yaml_input_path is not None:
        if input_path is not None:
            raise RuntimeError("Use either an architecture input file or a direct YAML input, not both.")
        if ai_architecture or openai_review or copilot_review:
            raise RuntimeError("Direct YAML input cannot be combined with AI drafting or AI review.")
        return _run_direct_yaml_input(
            yaml_input_path,
            output_dir=output_dir,
            threagile_docker=threagile_docker,
            threagile_image=threagile_image,
        )

    source = ""
    source_name = None
    if input_path is not None:
        source = input_path.read_text(encoding="utf-8")
        source_name = input_path.name

    if not source.strip() and not (architecture_notes or "").strip():
        raise RuntimeError("Provide an architecture input file or architecture notes before running the analysis.")
    if not source.strip() and not ai_architecture:
        raise RuntimeError("Architecture notes require AI architecture drafting when no input file is provided.")

    if source.strip():
        parsed_model = parse_architecture(source, source_name=source_name)
    else:
        parsed_model = ArchitectureModel(title="AI Generated Threat Model")

    ai_architecture_draft: AIArchitectureDraft | None = None
    model = parsed_model
    if ai_architecture:
        provider = ai_architecture_provider.strip().lower()
        if provider in {"copilot", "github", "github-copilot", "github_models", "github-models"}:
            ai_architecture_draft = draft_architecture_with_copilot(
                parsed_model,
                source_text=source,
                source_name=source_name,
                architecture_notes=architecture_notes,
                model_name=ai_architecture_model or copilot_model,
                api_key=copilot_api_key,
            )
        elif provider in {"openai", "chatgpt"}:
            ai_architecture_draft = draft_architecture_with_openai(
                parsed_model,
                source_text=source,
                source_name=source_name,
                architecture_notes=architecture_notes,
                model_name=ai_architecture_model or openai_model,
                api_key=openai_api_key,
            )
        else:
            raise RuntimeError("AI architecture provider must be 'openai' or 'copilot'.")
        model = ai_architecture_draft.architecture

    ai_reviews: list[AIReviewResult] = []
    if openai_review:
        ai_reviews.append(
            review_architecture_with_openai(
                model,
                model_name=openai_model,
                api_key=openai_api_key,
            )
        )
    if copilot_review:
        ai_reviews.append(
            review_architecture_with_copilot(
                model,
                model_name=copilot_model,
                api_key=copilot_api_key,
            )
        )

    assessment = build_assessment(model, ai_reviews=ai_reviews)
    threagile_model = build_threagile_yaml_model(model)

    output_dir.mkdir(parents=True, exist_ok=True)
    yaml_path = output_dir / "threagile-model.yaml"
    docker_yaml_path = output_dir / "threagile.yaml"
    report_path = output_dir / "architecture-review.md"
    ai_review_path = output_dir / "ai-review.json" if ai_reviews else None
    ai_architecture_path = output_dir / "ai-architecture.json" if ai_architecture_draft is not None else None

    yaml_text = dump_yaml(threagile_model) + "\n"
    yaml_path.write_text(yaml_text, encoding="utf-8")
    docker_yaml_path.write_text(yaml_text, encoding="utf-8")
    report_path.write_text(render_assessment_markdown(assessment), encoding="utf-8")
    if ai_architecture_path is not None and ai_architecture_draft is not None:
        ai_architecture_path.write_text(
            json.dumps(architecture_draft_to_dict(ai_architecture_draft), indent=2) + "\n",
            encoding="utf-8",
        )
    if ai_review_path is not None:
        ai_review_path.write_text(json.dumps(assessment["ai_reviews"], indent=2) + "\n", encoding="utf-8")
    threagile_pdf_path = None
    if threagile_docker:
        threagile_pdf_path = generate_threagile_pdf(
            docker_yaml_path,
            docker_image=threagile_image,
        )

    return RunResult(
        yaml_path=yaml_path,
        report_path=report_path,
        threagile_pdf_path=threagile_pdf_path,
        ai_review_path=ai_review_path,
        ai_reviews=ai_reviews,
        ai_architecture_path=ai_architecture_path,
        ai_architecture_draft=ai_architecture_draft,
    )


def _run_direct_yaml_input(
    yaml_input_path: Path,
    *,
    output_dir: Path,
    threagile_docker: bool,
    threagile_image: str,
) -> RunResult:
    yaml_text = yaml_input_path.read_text(encoding="utf-8")
    if not yaml_text.strip():
        raise RuntimeError(f"The direct YAML input is empty: {yaml_input_path}")

    yaml_payload = _load_yaml_mapping(yaml_text, yaml_input_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    yaml_path = output_dir / "threagile-model.yaml"
    docker_yaml_path = output_dir / "threagile.yaml"
    report_path = output_dir / "architecture-review.md"

    if _is_normalized_architecture_yaml(yaml_payload):
        model = _architecture_model_from_payload(yaml_payload, fallback_title=yaml_input_path.stem)
        assessment = build_assessment(model)
        rendered_yaml = dump_yaml(build_threagile_yaml_model(model)) + "\n"
        report_text = render_assessment_markdown(assessment)
    else:
        rendered_yaml = _shorten_threagile_map_labels(yaml_text)
        rendered_yaml = rendered_yaml if rendered_yaml.endswith("\n") else f"{rendered_yaml}\n"
        report_text = _render_direct_yaml_report(yaml_input_path, docker_yaml_path)

    yaml_path.write_text(rendered_yaml, encoding="utf-8")
    docker_yaml_path.write_text(rendered_yaml, encoding="utf-8")
    report_path.write_text(report_text, encoding="utf-8")

    threagile_pdf_path = None
    if threagile_docker:
        threagile_pdf_path = generate_threagile_pdf(
            docker_yaml_path,
            docker_image=threagile_image,
        )

    return RunResult(
        yaml_path=yaml_path,
        report_path=report_path,
        threagile_pdf_path=threagile_pdf_path,
        ai_review_path=None,
        ai_reviews=[],
    )


def _shorten_threagile_map_labels(yaml_text: str) -> str:
    sections = {"data_assets", "technical_assets", "trust_boundaries", "questions"}
    seen_by_section = {section: set() for section in sections}
    current_section: str | None = None
    rendered_lines: list[str] = []

    for line in yaml_text.splitlines():
        stripped = line.strip()
        if line and not line.startswith((" ", "\t", "-")):
            key, separator, value = stripped.partition(":")
            if separator and key == "title":
                rendered_lines.append(f"title: {_render_yaml_key(_fit_yaml_label(_parse_yaml_scalar(value), EXCEL_SHEET_NAME_LIMIT))}")
                current_section = None
                continue
            current_section = stripped[:-1] if stripped.endswith(":") else None
            rendered_lines.append(line)
            continue

        if current_section in sections and line.startswith("  ") and not line.startswith("    "):
            if stripped.endswith(":"):
                raw_label = stripped[:-1].strip('"')
                short_label = _unique_short_label(raw_label, seen_by_section[current_section])
                seen_by_section[current_section].add(short_label)
                rendered_lines.append(f"  {_render_yaml_key(short_label)}:")
                continue
            key, separator, value = stripped.partition(":")
            if separator and key:
                raw_label = key.strip('"')
                short_label = _unique_short_label(raw_label, seen_by_section[current_section])
                seen_by_section[current_section].add(short_label)
                rendered_lines.append(f"  {_render_yaml_key(short_label)}:{value}")
                continue

        rendered_lines.append(line)

    return "\n".join(rendered_lines)


def _unique_short_label(label: str, seen: set[str]) -> str:
    candidate = _fit_yaml_label(label, EXCEL_SHEET_NAME_LIMIT)
    if candidate not in seen:
        return candidate

    counter = 2
    while True:
        suffix = f" ({counter})"
        candidate = f"{_fit_yaml_label(label, EXCEL_SHEET_NAME_LIMIT - len(suffix))}{suffix}"
        if candidate not in seen:
            return candidate
        counter += 1


def _fit_yaml_label(label: str, max_length: int) -> str:
    text = label.strip() or "item"
    if len(text) <= max_length:
        return text
    return text[:max_length].rstrip(" .,:;-/") or text[:max_length]


def _render_yaml_key(label: str) -> str:
    if (
        not label
        or label[0] in {"-", "?", "@", "!", "&", "*"}
        or label.strip() != label
        or any(char in label for char in [":", "#", "{", "}", "[", "]", '"', "\n", "\r", "\t"])
    ):
        escaped = label.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return label


def _load_yaml_mapping(yaml_text: str, source_path: Path) -> dict[str, Any]:
    try:
        import yaml as yaml_parser
    except ModuleNotFoundError:
        if _looks_like_normalized_architecture_yaml(yaml_text):
            return _parse_normalized_architecture_yaml(yaml_text)
        return {}

    try:
        payload = yaml_parser.safe_load(yaml_text)
    except yaml_parser.YAMLError as exc:
        raise RuntimeError(f"The direct YAML input is not valid YAML: {source_path}. {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"The direct YAML input must be a YAML mapping/object: {source_path}")
    return payload


def _looks_like_normalized_architecture_yaml(yaml_text: str) -> bool:
    top_level_keys = set()
    for raw_line in yaml_text.splitlines():
        if raw_line.startswith((" ", "	", "-")):
            continue
        key, separator, _value = raw_line.partition(":")
        if separator:
            top_level_keys.add(key.strip())
    return {"components", "data_flows", "trust_boundaries"}.issubset(top_level_keys)


def _parse_normalized_architecture_yaml(yaml_text: str) -> dict[str, Any]:
    lines = [line.rstrip() for line in yaml_text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    payload: dict[str, Any] = {
        "title": "",
        "summary": "",
        "assumptions": [],
        "trust_boundaries": [],
        "components": [],
        "data_flows": [],
    }
    top_level_keys = set(payload)
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        key, separator, value = stripped.partition(":")
        if not separator or key not in top_level_keys:
            index += 1
            continue
        if key in {"title", "summary"}:
            value_parts = [_parse_yaml_scalar(value)] if value.strip() else []
            index += 1
            while index < len(lines) and not _is_top_level_key(lines[index], top_level_keys):
                if not lines[index].lstrip().startswith("-"):
                    value_parts.append(lines[index].strip())
                index += 1
            payload[key] = " ".join(part for part in value_parts if part).strip()
            continue
        if key in {"assumptions", "trust_boundaries"}:
            values, index = _parse_yaml_string_list(lines, index + 1, top_level_keys)
            payload[key] = values
            continue
        if key in {"components", "data_flows"}:
            values, index = _parse_yaml_object_list(lines, index + 1, top_level_keys)
            payload[key] = values
            continue
        index += 1
    return payload


def _parse_yaml_string_list(lines: list[str], index: int, top_level_keys: set[str]) -> tuple[list[str], int]:
    values: list[str] = []
    current: list[str] = []
    while index < len(lines) and not _is_top_level_key(lines[index], top_level_keys):
        stripped = lines[index].strip()
        if stripped.startswith("- "):
            if current:
                values.append(" ".join(current).strip())
            current = [_parse_yaml_scalar(stripped[2:])]
        elif current:
            current.append(stripped)
        index += 1
    if current:
        values.append(" ".join(current).strip())
    return values, index


def _parse_yaml_object_list(lines: list[str], index: int, top_level_keys: set[str]) -> tuple[list[dict[str, Any]], int]:
    values: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    list_field: str | None = None
    while index < len(lines) and not _is_top_level_key(lines[index], top_level_keys):
        stripped = lines[index].strip()
        if stripped.startswith("- ") and ":" in stripped[2:]:
            if current is not None:
                values.append(current)
            current = {}
            list_field = None
            _assign_yaml_field(current, stripped[2:])
        elif current is not None and stripped.startswith("- ") and list_field:
            current.setdefault(list_field, []).append(_parse_yaml_scalar(stripped[2:]))
        elif current is not None and ":" in stripped:
            field_name, _separator, field_value = stripped.partition(":")
            field_name = field_name.strip()
            if field_value.strip():
                current[field_name] = _parse_yaml_scalar(field_value)
                list_field = None
            else:
                current[field_name] = []
                list_field = field_name
        index += 1
    if current is not None:
        values.append(current)
    return values, index


def _assign_yaml_field(container: dict[str, Any], field_text: str) -> None:
    field_name, _separator, field_value = field_text.partition(":")
    container[field_name.strip()] = _parse_yaml_scalar(field_value)


def _parse_yaml_scalar(value: str) -> str:
    text = value.strip()
    if text in {"[]", "{}"}:
        return ""
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        text = text[1:-1]
    return text.replace('\"', '"')


def _is_top_level_key(line: str, top_level_keys: set[str]) -> bool:
    if line.startswith((" ", "	", "-")):
        return False
    key, separator, _value = line.strip().partition(":")
    return bool(separator) and key in top_level_keys


def _is_normalized_architecture_yaml(payload: dict[str, Any]) -> bool:
    return (
        isinstance(payload.get("components"), list)
        and isinstance(payload.get("data_flows"), list)
        and isinstance(payload.get("trust_boundaries"), list)
    )


def _render_direct_yaml_report(source_path: Path, model_path: Path) -> str:
    return "\n".join(
        [
            "# Direct Threagile YAML Input",
            "",
            "An existing Threagile YAML model was provided directly, so PlantUML parsing, architecture guidance, and AI review were skipped.",
            "",
            f"- Source YAML: `{source_path}`",
            f"- Docker model YAML: `{model_path}`",
            "",
            "Review the YAML content itself before relying on generated Docker/PDF output.",
            "",
        ]
    )
