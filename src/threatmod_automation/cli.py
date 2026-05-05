from __future__ import annotations

import argparse
from pathlib import Path

from .runner import run_analysis
from .threagile import DEFAULT_THREAGILE_IMAGE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Convert PlantUML/UML text or StarUML project/fragment files into a "
            "Threagile-compatible YAML model and guidance report."
        )
    )
    parser.add_argument(
        "input",
        type=Path,
        help="Path to a PlantUML/UML text file or StarUML .mdj/.mfj file.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Directory where YAML and report files will be written.",
    )
    parser.add_argument(
        "--ai-review",
        action="store_true",
        help="Request an additional ChatGPT architecture review before generating the final outputs.",
    )
    parser.add_argument(
        "--openai-model",
        default="gpt-5.2",
        help="OpenAI model to use for the optional AI review stage.",
    )
    parser.add_argument(
        "--copilot-review",
        action="store_true",
        help="Request an additional GitHub Copilot review through GitHub Models.",
    )
    parser.add_argument(
        "--copilot-model",
        default="openai/gpt-5.2",
        help="GitHub Models model to use for the optional Copilot review stage.",
    )
    parser.add_argument(
        "--threagile-docker",
        action="store_true",
        help="Run the official Threagile Docker image against the generated YAML and create the PDF report.",
    )
    parser.add_argument(
        "--threagile-image",
        default=DEFAULT_THREAGILE_IMAGE,
        help="Docker image to use when --threagile-docker is enabled.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    result = run_analysis(
        args.input,
        output_dir=args.output_dir,
        openai_review=args.ai_review,
        openai_model=args.openai_model,
        copilot_review=args.copilot_review,
        copilot_model=args.copilot_model,
        threagile_docker=args.threagile_docker,
        threagile_image=args.threagile_image,
    )

    print(f"Wrote {result.yaml_path}")
    print(f"Wrote {result.report_path}")
    if result.threagile_pdf_path is not None:
        print(f"Wrote {result.threagile_pdf_path}")
    if result.ai_review_path is not None:
        print(f"Wrote {result.ai_review_path}")


if __name__ == "__main__":
    main()
