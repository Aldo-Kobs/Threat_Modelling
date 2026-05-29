from __future__ import annotations

import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from .runner import run_analysis
from .threagile import DEFAULT_THREAGILE_IMAGE


WORKFLOW_IMPORT = "Import file"
WORKFLOW_AI_DRAFT = "AI draft from description"
WORKFLOW_IMPORT_AND_AI = "Import file + AI draft"
WORKFLOW_DIRECT_YAML = "YAML input"
PROVIDER_OPENAI = "OpenAI"
PROVIDER_COPILOT = "GitHub Copilot"


class ThreatmodApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Threatmod Assistant")
        self.root.geometry("1080x860")

        self.input_path = tk.StringVar(value=str(Path("examples/vehicle_gateway.puml").resolve()))
        self.yaml_input_path = tk.StringVar()
        self.output_dir = tk.StringVar(value=str(Path("output").resolve()))
        self.workflow_mode = tk.StringVar(value=WORKFLOW_IMPORT)
        self.architecture_provider = tk.StringVar(value=PROVIDER_OPENAI)
        self.openai_review = tk.BooleanVar(value=False)
        self.copilot_review = tk.BooleanVar(value=False)
        self.threagile_docker = tk.BooleanVar(value=False)
        self.openai_model = tk.StringVar(value="gpt-5.2")
        self.copilot_model = tk.StringVar(value="openai/gpt-5.2")
        self.threagile_image = tk.StringVar(value=DEFAULT_THREAGILE_IMAGE)
        self.openai_api_key = tk.StringVar()
        self.copilot_api_key = tk.StringVar()
        self.status = tk.StringVar(value="Choose a workflow and run the analysis.")
        self.threagile_pdf_path: Path | None = None

        self._build_layout()
        self._sync_workflow_controls()

    def _build_layout(self) -> None:
        frame = ttk.Frame(self.root, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(9, weight=1)

        ttk.Label(frame, text="Threat Modelling Automation", font=("TkDefaultFont", 15, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 12)
        )

        ttk.Label(frame, text="Architecture input").grid(row=1, column=0, sticky="w", pady=4)
        self.input_entry = ttk.Entry(frame, textvariable=self.input_path)
        self.input_entry.grid(row=1, column=1, sticky="ew", padx=8)
        self.input_button = ttk.Button(frame, text="Browse", command=self._browse_input)
        self.input_button.grid(row=1, column=2, sticky="ew")

        ttk.Label(frame, text="YAML input").grid(row=2, column=0, sticky="w", pady=4)
        self.yaml_input_entry = ttk.Entry(frame, textvariable=self.yaml_input_path)
        self.yaml_input_entry.grid(row=2, column=1, sticky="ew", padx=8)
        self.yaml_input_button = ttk.Button(frame, text="Browse", command=self._browse_yaml_input)
        self.yaml_input_button.grid(row=2, column=2, sticky="ew")

        ttk.Label(frame, text="Output directory").grid(row=3, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.output_dir).grid(row=3, column=1, sticky="ew", padx=8)
        ttk.Button(frame, text="Browse", command=self._browse_output).grid(row=3, column=2, sticky="ew")

        workflow = ttk.LabelFrame(frame, text="Workflow", padding=12)
        workflow.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(12, 8))
        workflow.columnconfigure(1, weight=1)

        ttk.Label(workflow, text="Mode").grid(row=0, column=0, sticky="w")
        mode_combo = ttk.Combobox(
            workflow,
            textvariable=self.workflow_mode,
            values=(WORKFLOW_IMPORT, WORKFLOW_AI_DRAFT, WORKFLOW_IMPORT_AND_AI, WORKFLOW_DIRECT_YAML),
            state="readonly",
        )
        mode_combo.grid(row=0, column=1, sticky="ew", padx=(8, 0))
        mode_combo.bind("<<ComboboxSelected>>", self._sync_workflow_controls)

        ttk.Label(workflow, text="Architecture AI").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.architecture_provider_combo = ttk.Combobox(
            workflow,
            textvariable=self.architecture_provider,
            values=(PROVIDER_OPENAI, PROVIDER_COPILOT),
            state="readonly",
        )
        self.architecture_provider_combo.grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=(8, 0))
        ttk.Label(workflow, text="Uses matching key and model below").grid(
            row=1, column=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )

        ttk.Label(workflow, text="Architecture notes").grid(row=2, column=0, sticky="nw", pady=(8, 0))
        notes_frame = ttk.Frame(workflow)
        notes_frame.grid(row=2, column=1, columnspan=2, sticky="ew", padx=(8, 0), pady=(8, 0))
        notes_frame.columnconfigure(0, weight=1)
        self.architecture_notes_text = tk.Text(notes_frame, height=4, wrap="word")
        self.architecture_notes_text.grid(row=0, column=0, sticky="ew")
        notes_scrollbar = ttk.Scrollbar(notes_frame, orient=tk.VERTICAL, command=self.architecture_notes_text.yview)
        notes_scrollbar.grid(row=0, column=1, sticky="ns")
        self.architecture_notes_text.configure(yscrollcommand=notes_scrollbar.set)

        reviewers = ttk.LabelFrame(frame, text="Reviewers", padding=12)
        reviewers.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(8, 8))
        reviewers.columnconfigure(1, weight=1)

        self.openai_review_check = ttk.Checkbutton(reviewers, text="OpenAI review", variable=self.openai_review)
        self.openai_review_check.grid(row=0, column=0, sticky="w")
        ttk.Entry(reviewers, textvariable=self.openai_model).grid(row=0, column=1, sticky="ew", padx=(8, 0))
        ttk.Label(reviewers, text="Model").grid(row=0, column=2, sticky="w", padx=(8, 0))
        ttk.Label(reviewers, text="OpenAI key").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(reviewers, textvariable=self.openai_api_key, show="*").grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=(8, 0))
        ttk.Label(reviewers, text="Used only for this run").grid(row=1, column=2, sticky="w", padx=(8, 0), pady=(8, 0))

        self.copilot_review_check = ttk.Checkbutton(reviewers, text="GitHub Copilot review", variable=self.copilot_review)
        self.copilot_review_check.grid(row=2, column=0, sticky="w", pady=(12, 0))
        ttk.Entry(reviewers, textvariable=self.copilot_model).grid(row=2, column=1, sticky="ew", padx=(8, 0), pady=(12, 0))
        ttk.Label(reviewers, text="Model").grid(row=2, column=2, sticky="w", padx=(8, 0), pady=(12, 0))
        ttk.Label(reviewers, text="GitHub token").grid(row=3, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(reviewers, textvariable=self.copilot_api_key, show="*").grid(row=3, column=1, sticky="ew", padx=(8, 0), pady=(8, 0))
        ttk.Label(reviewers, text="Used only for this run").grid(row=3, column=2, sticky="w", padx=(8, 0), pady=(8, 0))

        threagile = ttk.LabelFrame(frame, text="Threagile Docker", padding=12)
        threagile.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(8, 8))
        threagile.columnconfigure(1, weight=1)

        ttk.Checkbutton(
            threagile,
            text="Generate Threagile PDF via Docker",
            variable=self.threagile_docker,
        ).grid(row=0, column=0, sticky="w")
        ttk.Entry(threagile, textvariable=self.threagile_image).grid(row=0, column=1, sticky="ew", padx=(8, 0))
        ttk.Label(threagile, text="Docker image").grid(row=0, column=2, sticky="w", padx=(8, 0))
        ttk.Label(
            threagile,
            text="Requires a local docker command and writes the generated PDF into the selected output directory.",
            justify=tk.LEFT,
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))

        button_row = ttk.Frame(frame)
        button_row.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(4, 8))
        button_row.columnconfigure(3, weight=1)
        self.run_button = ttk.Button(button_row, text="Run Analysis", command=self._start_analysis)
        self.run_button.grid(row=0, column=0, sticky="w")
        ttk.Button(button_row, text="Load Example", command=self._load_example).grid(row=0, column=1, sticky="w", padx=(8, 0))
        self.open_pdf_button = ttk.Button(
            button_row,
            text="Open Threagile PDF",
            command=self._open_threagile_pdf,
            state=tk.DISABLED,
        )
        self.open_pdf_button.grid(row=0, column=2, sticky="w", padx=(8, 0))

        ttk.Label(frame, textvariable=self.status).grid(row=8, column=0, columnspan=3, sticky="w", pady=(0, 8))

        output_box = ttk.LabelFrame(frame, text="Generated Guidance", padding=8)
        output_box.grid(row=9, column=0, columnspan=3, sticky="nsew")
        output_box.rowconfigure(0, weight=1)
        output_box.columnconfigure(0, weight=1)

        self.output_text = tk.Text(output_box, wrap="word")
        self.output_text.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(output_box, orient=tk.VERTICAL, command=self.output_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.output_text.configure(yscrollcommand=scrollbar.set)

    def _browse_input(self) -> None:
        filename = filedialog.askopenfilename(
            title="Select architecture file",
            filetypes=[
                ("Supported files", "*.puml *.uml *.txt *.mdj *.mfj"),
                ("PlantUML text", "*.puml *.uml *.txt"),
                ("StarUML files", "*.mdj *.mfj"),
                ("All files", "*.*"),
            ],
        )
        if filename:
            self.input_path.set(filename)

    def _browse_yaml_input(self) -> None:
        filename = filedialog.askopenfilename(
            title="Select YAML file",
            filetypes=[
                ("YAML files", "*.yaml *.yml"),
                ("All files", "*.*"),
            ],
        )
        if filename:
            self.yaml_input_path.set(filename)

    def _browse_output(self) -> None:
        directory = filedialog.askdirectory(title="Select output directory")
        if directory:
            self.output_dir.set(directory)

    def _load_example(self) -> None:
        self.workflow_mode.set(WORKFLOW_IMPORT)
        self.input_path.set(str(Path("examples/vehicle_gateway.puml").resolve()))
        self.yaml_input_path.set("")
        self._sync_workflow_controls()

    def _sync_workflow_controls(self, *_args: object) -> None:
        ai_enabled = self._uses_ai_architecture()
        direct_yaml = self._uses_direct_yaml()
        file_input_enabled = self._uses_file_input()

        self.architecture_provider_combo.configure(state="readonly" if ai_enabled else tk.DISABLED)
        self.architecture_notes_text.configure(state=tk.NORMAL if ai_enabled else tk.DISABLED)
        self.input_entry.configure(state=tk.NORMAL if file_input_enabled else tk.DISABLED)
        self.input_button.configure(state=tk.NORMAL if file_input_enabled else tk.DISABLED)
        self.yaml_input_entry.configure(state=tk.NORMAL if direct_yaml else tk.DISABLED)
        self.yaml_input_button.configure(state=tk.NORMAL if direct_yaml else tk.DISABLED)

        if direct_yaml:
            self.openai_review.set(False)
            self.copilot_review.set(False)
        review_state = tk.DISABLED if direct_yaml else tk.NORMAL
        self.openai_review_check.configure(state=review_state)
        self.copilot_review_check.configure(state=review_state)

    def _uses_ai_architecture(self) -> bool:
        return self.workflow_mode.get() in {WORKFLOW_AI_DRAFT, WORKFLOW_IMPORT_AND_AI}

    def _uses_direct_yaml(self) -> bool:
        return self.workflow_mode.get() == WORKFLOW_DIRECT_YAML

    def _uses_file_input(self) -> bool:
        return self.workflow_mode.get() not in {WORKFLOW_AI_DRAFT, WORKFLOW_DIRECT_YAML}

    def _architecture_provider_id(self) -> str:
        if self.architecture_provider.get() == PROVIDER_COPILOT:
            return "copilot"
        return "openai"

    def _architecture_model_name(self) -> str | None:
        if self._architecture_provider_id() == "copilot":
            return self.copilot_model.get().strip() or "openai/gpt-5.2"
        return self.openai_model.get().strip() or "gpt-5.2"

    def _architecture_notes(self) -> str:
        return self.architecture_notes_text.get("1.0", tk.END).strip()

    def _start_analysis(self) -> None:
        input_path: Path | None = None
        yaml_input_path: Path | None = None
        if self._uses_direct_yaml():
            yaml_input_text = self.yaml_input_path.get().strip()
            if not yaml_input_text:
                messagebox.showerror("YAML Input Missing", "Select a YAML input file for this workflow.")
                return
            yaml_input_path = Path(yaml_input_text)
            if not yaml_input_path.exists():
                messagebox.showerror("YAML Input Missing", "The selected YAML file does not exist.")
                return
        elif self._uses_file_input():
            input_text = self.input_path.get().strip()
            if not input_text:
                messagebox.showerror("Input Missing", "Select an architecture input file for this workflow.")
                return
            input_path = Path(input_text)
            if not input_path.exists():
                messagebox.showerror("Input Missing", "The selected architecture input file does not exist.")
                return

        architecture_notes = self._architecture_notes() if self._uses_ai_architecture() else ""
        if self.workflow_mode.get() == WORKFLOW_AI_DRAFT and not architecture_notes:
            messagebox.showerror("Architecture Notes Missing", "Add architecture notes before running an AI-only draft.")
            return

        openai_api_key = self.openai_api_key.get().strip()
        copilot_api_key = self.copilot_api_key.get().strip()
        ai_architecture_provider = self._architecture_provider_id()

        if self._uses_ai_architecture() and ai_architecture_provider == "openai" and not openai_api_key:
            messagebox.showerror("OpenAI Key Missing", "Paste an OpenAI API key to run the AI architecture draft.")
            return
        if self._uses_ai_architecture() and ai_architecture_provider == "copilot" and not copilot_api_key:
            messagebox.showerror("GitHub Token Missing", "Paste a GitHub Models or GitHub token to run the AI architecture draft.")
            return
        if self.openai_review.get() and not openai_api_key:
            messagebox.showerror("OpenAI Key Missing", "Paste an OpenAI API key to run the OpenAI review.")
            return
        if self.copilot_review.get() and not copilot_api_key:
            messagebox.showerror("GitHub Token Missing", "Paste a GitHub Models or GitHub token to run the Copilot review.")
            return

        run_config = {
            "input_path": input_path,
            "output_dir": Path(self.output_dir.get()),
            "yaml_input_path": yaml_input_path,
            "architecture_notes": architecture_notes,
            "ai_architecture": self._uses_ai_architecture(),
            "ai_architecture_provider": ai_architecture_provider,
            "ai_architecture_model": self._architecture_model_name(),
            "openai_review": self.openai_review.get(),
            "openai_model": self.openai_model.get().strip() or "gpt-5.2",
            "openai_api_key": openai_api_key or None,
            "copilot_review": self.copilot_review.get(),
            "copilot_model": self.copilot_model.get().strip() or "openai/gpt-5.2",
            "copilot_api_key": copilot_api_key or None,
            "threagile_docker": self.threagile_docker.get(),
            "threagile_image": self.threagile_image.get().strip() or DEFAULT_THREAGILE_IMAGE,
        }

        self.run_button.configure(state=tk.DISABLED)
        self.status.set("Running YAML workflow..." if self._uses_direct_yaml() else "Running architecture workflow...")
        self.output_text.delete("1.0", tk.END)
        self.threagile_pdf_path = None
        self.open_pdf_button.configure(state=tk.DISABLED)

        worker = threading.Thread(target=self._run_analysis_worker, args=(run_config,), daemon=True)
        worker.start()

    def _run_analysis_worker(self, run_config: dict[str, Any]) -> None:
        try:
            result = run_analysis(**run_config)
            report_text = result.report_path.read_text(encoding="utf-8")
            header_text = ""
            output_dir = Path(run_config["output_dir"]).resolve()
            message = f"Completed. Files written to {output_dir}"
            if result.ai_architecture_path is not None:
                header_text += f"AI architecture draft: {result.ai_architecture_path}\n"
                message = f"{message} | AI draft: {result.ai_architecture_path.name}"
            if result.threagile_pdf_path is not None:
                header_text += f"Threagile PDF: {result.threagile_pdf_path}\n"
                message = f"{message} | PDF: {result.threagile_pdf_path.name}"
            if header_text:
                header_text += "\n"
            self.root.after(
                0,
                self._finish_success,
                header_text + report_text,
                message,
                str(result.threagile_pdf_path) if result.threagile_pdf_path is not None else "",
            )
        except Exception as exc:  # pragma: no cover - UI flow
            self.root.after(0, self._finish_error, str(exc))

    def _finish_success(self, report_text: str, message: str, pdf_path: str) -> None:
        self.output_text.insert("1.0", report_text)
        self.status.set(message)
        self.run_button.configure(state=tk.NORMAL)
        self.threagile_pdf_path = Path(pdf_path) if pdf_path else None
        self.open_pdf_button.configure(state=tk.NORMAL if self.threagile_pdf_path else tk.DISABLED)
        self.openai_api_key.set("")
        self.copilot_api_key.set("")

    def _finish_error(self, error_text: str) -> None:
        self.status.set("Analysis failed.")
        self.run_button.configure(state=tk.NORMAL)
        self.threagile_pdf_path = None
        self.open_pdf_button.configure(state=tk.DISABLED)
        self.output_text.insert("1.0", error_text)
        self.openai_api_key.set("")
        self.copilot_api_key.set("")
        messagebox.showerror("Threatmod Error", error_text)

    def _open_threagile_pdf(self) -> None:
        if self.threagile_pdf_path is None or not self.threagile_pdf_path.exists():
            messagebox.showerror("PDF Missing", "No generated Threagile PDF is available for this run.")
            self.open_pdf_button.configure(state=tk.DISABLED)
            return
        webbrowser.open(self.threagile_pdf_path.resolve().as_uri())


def main() -> None:
    root = tk.Tk()
    app = ThreatmodApp(root)
    app._load_example()
    root.mainloop()


if __name__ == "__main__":
    main()
