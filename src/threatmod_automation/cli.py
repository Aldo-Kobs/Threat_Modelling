from __future__ import annotations

import argparse
from pathlib import Path

from .runner import run_analysis
from .threagile import DEFAULT_THREAGILE_IMAGE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Convert PlantUML/UML text, StarUML project/fragment files, or normalized "
            "architecture YAML into a Threagile-compatible YAML model and guidance report."
        )
    )
    parser.add_argument(
        "input",
        nargs="?",
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
        "--yaml-input",
        type=Path,
        help=(
            "Path to normalized architecture YAML or an existing Threagile YAML model. "
            "Normalized architecture YAML is converted before Docker runs."
        ),
    )
    parser.add_argument(
        "--ai-architecture",
        action="store_true",
        help="Ask AI to draft a normalized architecture before the Threagile YAML template is generated.",
    )
    parser.add_argument(
        "--architecture-provider",
        choices=("openai", "copilot"),
        default="openai",
        help="AI provider for --ai-architecture.",
    )
    parser.add_argument(
        "--architecture-model",
        default=None,
        help="Model to use for --ai-architecture. Defaults to --openai-model or --copilot-model based on provider.",
    )
    parser.add_argument(
        "--architecture-notes",
        default="",
        help="Free-form architecture notes to give the AI architecture draft step.",
    )
    parser.add_argument(
        "--architecture-notes-file",
        type=Path,
        help="Path to a text file containing architecture notes for the AI architecture draft step.",
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
    parser = build_parser()
    args = parser.parse_args()
    architecture_notes = args.architecture_notes or ""
    if args.architecture_notes_file is not None:
        file_notes = args.architecture_notes_file.read_text(encoding="utf-8")
        architecture_notes = "\n\n".join(part for part in [architecture_notes.strip(), file_notes.strip()] if part)
    if args.yaml_input is not None and args.input is not None:
        parser.error("use either the input argument or --yaml-input, not both.")
    if args.yaml_input is not None and (args.ai_architecture or args.ai_review or args.copilot_review):
        parser.error("--yaml-input cannot be combined with AI architecture drafting or AI review.")
    if args.input is None and args.yaml_input is None and not args.ai_architecture:
        parser.error("the input argument is required unless --ai-architecture is enabled.")
    if args.input is None and args.yaml_input is None and not architecture_notes.strip():
        parser.error("--architecture-notes or --architecture-notes-file is required without an input file.")

    result = run_analysis(
        args.input,
        output_dir=args.output_dir,
        yaml_input_path=args.yaml_input,
        architecture_notes=architecture_notes,
        ai_architecture=args.ai_architecture,
        ai_architecture_provider=args.architecture_provider,
        ai_architecture_model=args.architecture_model,
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
    if result.ai_architecture_path is not None:
        print(f"Wrote {result.ai_architecture_path}")
    if result.ai_review_path is not None:
        print(f"Wrote {result.ai_review_path}")


if __name__ == "__main__":
    main()
