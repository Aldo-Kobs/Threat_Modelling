from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .ai_review import AIReviewResult, review_architecture_with_copilot, review_architecture_with_openai
from .guidance import build_assessment, render_assessment_markdown
from .parser import parse_architecture
from .threagile import DEFAULT_THREAGILE_IMAGE, build_threagile_yaml_model, generate_threagile_pdf
from .yaml_writer import dump_yaml


@dataclass(slots=True)
class RunResult:
    yaml_path: Path
    report_path: Path
    threagile_pdf_path: Path | None
    ai_review_path: Path | None
    ai_reviews: list[AIReviewResult]


def run_analysis(
    input_path: Path,
    *,
    output_dir: Path,
    openai_review: bool = False,
    openai_model: str = "gpt-5.2",
    openai_api_key: str | None = None,
    copilot_review: bool = False,
    copilot_model: str = "openai/gpt-5.2",
    copilot_api_key: str | None = None,
    threagile_docker: bool = False,
    threagile_image: str = DEFAULT_THREAGILE_IMAGE,
) -> RunResult:
    source = input_path.read_text(encoding="utf-8")
    model = parse_architecture(source, source_name=input_path.name)

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

    yaml_text = dump_yaml(threagile_model) + "\n"
    yaml_path.write_text(yaml_text, encoding="utf-8")
    docker_yaml_path.write_text(yaml_text, encoding="utf-8")
    report_path.write_text(render_assessment_markdown(assessment), encoding="utf-8")
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
    )
