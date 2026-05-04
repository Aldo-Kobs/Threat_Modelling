import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threatmod_automation.ai_review import AIReviewResult
from threatmod_automation.ai_review import _extract_output_text
from threatmod_automation.ai_review import _extract_github_models_text
from threatmod_automation.guidance import build_assessment
from threatmod_automation.guidance import render_assessment_markdown
from threatmod_automation.parser import parse_plantuml
from threatmod_automation.runner import run_analysis
from threatmod_automation.threagile import build_threagile_yaml_model
from threatmod_automation.yaml_writer import dump_yaml


SAMPLE = """
@startuml
title Sample
package "Control Zone" {
  device "PLC" as plc
  component "HMI" as hmi
}
actor "Operator" as operator
database "Historian" as historian
operator --> hmi : HTTPS
hmi --> plc : OPCUA
plc --> historian : TCP
@enduml
"""


class PipelineTests(unittest.TestCase):
    def test_pipeline_builds_assets_and_guidance(self) -> None:
        model = parse_plantuml(SAMPLE)
        assessment = build_assessment(model)
        threagile = build_threagile_yaml_model(model)
        rendered = dump_yaml(threagile)

        self.assertEqual(model.title, "Sample")
        self.assertIn("plc", model.components)
        self.assertEqual(len(model.data_flows), 3)
        self.assertTrue(assessment["coverage"]["has_network_boundary"])
        self.assertIn("technical_assets:", rendered)
        self.assertIn("trust_boundaries:", rendered)
        self.assertEqual(threagile["technical_assets"]["PLC"]["technology"], "iot-device")
        self.assertEqual(threagile["technical_assets"]["Historian"]["type"], "datastore")
        self.assertEqual(
            threagile["trust_boundaries"]["Control Zone"]["technical_assets_inside"],
            ["hmi", "plc"],
        )

    def test_threagile_ids_are_slugified_for_aliases_and_references(self) -> None:
        sample = """
@startuml
title Slugify
package "Vehicle Zone" {
  device "Brake ECU" as brake_ecu
  database "Telemetry Store" as telemetry.db
}
brake_ecu --> telemetry.db : TCP
@enduml
"""
        model = parse_plantuml(sample)
        threagile = build_threagile_yaml_model(model)

        self.assertEqual(threagile["technical_assets"]["Brake ECU"]["id"], "brake-ecu")
        self.assertEqual(threagile["technical_assets"]["Telemetry Store"]["id"], "telemetry-db")
        self.assertEqual(
            threagile["technical_assets"]["Brake ECU"]["communication_links"]["Flow 1"]["target"],
            "telemetry-db",
        )
        self.assertEqual(
            threagile["trust_boundaries"]["Vehicle Zone"]["technical_assets_inside"],
            ["brake-ecu", "telemetry-db"],
        )

    def test_assessment_renders_ai_review_sections(self) -> None:
        model = parse_plantuml(SAMPLE)
        ai_review = AIReviewResult(
            enabled=True,
            provider="OpenAI",
            model="gpt-5.1",
            summary="The architecture has a basic control path but needs more operational detail.",
            current_status=["Core components and data flows are present."],
            possible_missing_components=["Engineering workstation", "Firewall or jump host"],
            possible_missing_connections=["Remote maintenance path to PLC"],
            impacts_to_investigate=["Unauthorized control commands to PLC"],
            suggested_countermeasures=["Mutual authentication on operator and maintenance channels"],
        )

        assessment = build_assessment(model, ai_review=ai_review)
        self.assertIn("ai_reviews", assessment)
        markdown = render_assessment_markdown(assessment)
        self.assertIn("## AI Reviews", markdown)
        self.assertIn("### OpenAI", markdown)
        self.assertIn("Engineering workstation", markdown)

    def test_extract_output_text_reads_response_output_array(self) -> None:
        payload = {
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": '{"summary":"ok","current_status":[],"possible_missing_components":[],"possible_missing_connections":[],"impacts_to_investigate":[],"suggested_countermeasures":[]}',
                        }
                    ],
                }
            ],
        }

        extracted = _extract_output_text(payload)
        self.assertIn('"summary":"ok"', extracted)

    def test_extract_github_models_text_reads_choices(self) -> None:
        payload = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": '{"summary":"copilot-ok","current_status":[],"possible_missing_components":[],"possible_missing_connections":[],"impacts_to_investigate":[],"suggested_countermeasures":[]}',
                    }
                }
            ]
        }

        extracted = _extract_github_models_text(payload)
        self.assertIn('"summary":"copilot-ok"', extracted)

    def test_runner_writes_expected_output_files(self) -> None:
        input_path = Path("examples/test-sample.puml")
        input_path.write_text(SAMPLE, encoding="utf-8")
        output_dir = Path("output/test-runner")

        result = run_analysis(input_path, output_dir=output_dir)

        self.assertTrue(result.yaml_path.exists())
        self.assertTrue((output_dir / "threagile.yaml").exists())
        self.assertTrue(result.report_path.exists())
        self.assertIsNone(result.threagile_pdf_path)
        self.assertIsNone(result.ai_review_path)
        self.assertIn("Coverage Summary", result.report_path.read_text(encoding="utf-8"))

    def test_runner_can_generate_threagile_pdf_via_docker(self) -> None:
        input_path = Path("examples/test-sample.puml")
        input_path.write_text(SAMPLE, encoding="utf-8")
        output_dir = Path("output/test-runner-docker")

        def fake_run(command, capture_output, text, check):
            self.assertIn("docker", command[0])
            self.assertIn("--mount", command)
            self.assertIn("--model", command)
            self.assertIn("--output", command)
            self.assertIn("/app/work/threagile.yaml", command)
            (output_dir / "report.pdf").write_text("fake pdf placeholder", encoding="utf-8")
            return mock.Mock()

        with mock.patch("threatmod_automation.threagile.shutil.which", return_value="/usr/bin/docker"):
            with mock.patch("threatmod_automation.threagile.subprocess.run", side_effect=fake_run):
                result = run_analysis(
                    input_path,
                    output_dir=output_dir,
                    threagile_docker=True,
                )

        self.assertEqual(result.threagile_pdf_path, output_dir.resolve() / "report.pdf")
        self.assertTrue(result.threagile_pdf_path.exists())
