from __future__ import annotations

import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .runner import run_analysis
from .threagile import DEFAULT_THREAGILE_IMAGE


class ThreatmodApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Threatmod Assistant")
        self.root.geometry("980x720")

        self.input_path = tk.StringVar(value=str(Path("examples/vehicle_gateway.puml").resolve()))
        self.output_dir = tk.StringVar(value=str(Path("output").resolve()))
        self.openai_review = tk.BooleanVar(value=False)
        self.copilot_review = tk.BooleanVar(value=False)
        self.threagile_docker = tk.BooleanVar(value=False)
        self.openai_model = tk.StringVar(value="gpt-5.2")
        self.copilot_model = tk.StringVar(value="openai/gpt-5.2")
        self.threagile_image = tk.StringVar(value=DEFAULT_THREAGILE_IMAGE)
        self.openai_api_key = tk.StringVar()
        self.copilot_api_key = tk.StringVar()
        self.status = tk.StringVar(value="Choose an architecture file and run the analysis.")
        self.threagile_pdf_path: Path | None = None

        self._build_layout()

    def _build_layout(self) -> None:
        frame = ttk.Frame(self.root, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(8, weight=1)

        ttk.Label(frame, text="Threat Modelling Automation", font=("TkDefaultFont", 15, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 12)
        )

        ttk.Label(frame, text="UML / PlantUML input").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.input_path).grid(row=1, column=1, sticky="ew", padx=8)
        ttk.Button(frame, text="Browse", command=self._browse_input).grid(row=1, column=2, sticky="ew")

        ttk.Label(frame, text="Output directory").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.output_dir).grid(row=2, column=1, sticky="ew", padx=8)
        ttk.Button(frame, text="Browse", command=self._browse_output).grid(row=2, column=2, sticky="ew")

        reviewers = ttk.LabelFrame(frame, text="Reviewers", padding=12)
        reviewers.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(12, 8))
        reviewers.columnconfigure(1, weight=1)

        ttk.Checkbutton(reviewers, text="OpenAI review", variable=self.openai_review).grid(row=0, column=0, sticky="w")
        ttk.Entry(reviewers, textvariable=self.openai_model).grid(row=0, column=1, sticky="ew", padx=(8, 0))
        ttk.Label(reviewers, text="Model").grid(row=0, column=2, sticky="w", padx=(8, 0))
        ttk.Label(reviewers, text="OpenAI key").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(reviewers, textvariable=self.openai_api_key, show="*").grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=(8, 0))
        ttk.Label(reviewers, text="Used only for this run").grid(row=1, column=2, sticky="w", padx=(8, 0), pady=(8, 0))

        ttk.Checkbutton(reviewers, text="GitHub Copilot review", variable=self.copilot_review).grid(row=2, column=0, sticky="w", pady=(12, 0))
        ttk.Entry(reviewers, textvariable=self.copilot_model).grid(row=2, column=1, sticky="ew", padx=(8, 0), pady=(12, 0))
        ttk.Label(reviewers, text="Model").grid(row=2, column=2, sticky="w", padx=(8, 0), pady=(12, 0))
        ttk.Label(reviewers, text="GitHub token").grid(row=3, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(reviewers, textvariable=self.copilot_api_key, show="*").grid(row=3, column=1, sticky="ew", padx=(8, 0), pady=(8, 0))
        ttk.Label(reviewers, text="Used only for this run").grid(row=3, column=2, sticky="w", padx=(8, 0), pady=(8, 0))

        threagile = ttk.LabelFrame(frame, text="Threagile Docker", padding=12)
        threagile.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(8, 8))
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

        hints = ttk.LabelFrame(frame, text="Run Hints", padding=12)
        hints.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(8, 8))
        hints.columnconfigure(0, weight=1)
        ttk.Label(
            hints,
            text=(
                "1. Pick a UML/PlantUML file.\n"
                "2. Choose optional reviewers and paste keys if needed.\n"
                "3. Optionally enable the Threagile Docker PDF run.\n"
                "4. Click Run Analysis.\n"
                "5. Read the generated guidance in the lower pane."
            ),
            justify=tk.LEFT,
        ).grid(row=0, column=0, sticky="w")

        button_row = ttk.Frame(frame)
        button_row.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(4, 8))
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

        ttk.Label(frame, textvariable=self.status).grid(row=7, column=0, columnspan=3, sticky="w", pady=(0, 8))

        output_box = ttk.LabelFrame(frame, text="Generated Guidance", padding=8)
        output_box.grid(row=8, column=0, columnspan=3, sticky="nsew")
        output_box.rowconfigure(0, weight=1)
        output_box.columnconfigure(0, weight=1)

        self.output_text = tk.Text(output_box, wrap="word")
        self.output_text.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(output_box, orient=tk.VERTICAL, command=self.output_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.output_text.configure(yscrollcommand=scrollbar.set)

    def _browse_input(self) -> None:
        filename = filedialog.askopenfilename(
            title="Select UML or PlantUML file",
            filetypes=[("PlantUML files", "*.puml *.uml *.txt"), ("All files", "*.*")],
        )
        if filename:
            self.input_path.set(filename)

    def _browse_output(self) -> None:
        directory = filedialog.askdirectory(title="Select output directory")
        if directory:
            self.output_dir.set(directory)

    def _load_example(self) -> None:
        self.input_path.set(str(Path("examples/vehicle_gateway.puml").resolve()))

    def _start_analysis(self) -> None:
        input_path = Path(self.input_path.get())
        if not input_path.exists():
            messagebox.showerror("Input Missing", "The selected UML/PlantUML input file does not exist.")
            return

        if self.openai_review.get() and not self.openai_api_key.get().strip():
            messagebox.showerror("OpenAI Key Missing", "Paste an OpenAI API key to run the OpenAI review.")
            return
        if self.copilot_review.get() and not self.copilot_api_key.get().strip():
            messagebox.showerror("GitHub Token Missing", "Paste a GitHub Models or GitHub token to run the Copilot review.")
            return

        self.run_button.configure(state=tk.DISABLED)
        self.status.set("Running analysis...")
        self.output_text.delete("1.0", tk.END)
        self.threagile_pdf_path = None
        self.open_pdf_button.configure(state=tk.DISABLED)

        worker = threading.Thread(target=self._run_analysis_worker, daemon=True)
        worker.start()

    def _run_analysis_worker(self) -> None:
        try:
            result = run_analysis(
                Path(self.input_path.get()),
                output_dir=Path(self.output_dir.get()),
                openai_review=self.openai_review.get(),
                openai_model=self.openai_model.get().strip() or "gpt-5.2",
                openai_api_key=self.openai_api_key.get().strip() or None,
                copilot_review=self.copilot_review.get(),
                copilot_model=self.copilot_model.get().strip() or "openai/gpt-5.2",
                copilot_api_key=self.copilot_api_key.get().strip() or None,
                threagile_docker=self.threagile_docker.get(),
                threagile_image=self.threagile_image.get().strip() or DEFAULT_THREAGILE_IMAGE,
            )
            report_text = result.report_path.read_text(encoding="utf-8")
            pdf_text = ""
            if result.threagile_pdf_path is not None:
                pdf_text = f"Threagile PDF: {result.threagile_pdf_path}\n\n"
            message = f"Completed. Files written to {Path(self.output_dir.get()).resolve()}"
            if result.threagile_pdf_path is not None:
                message = f"{message} | PDF: {result.threagile_pdf_path.name}"
            self.root.after(
                0,
                self._finish_success,
                pdf_text + report_text,
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
