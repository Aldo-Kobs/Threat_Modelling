import json
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
from threatmod_automation.parser import parse_architecture
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

STARUML_PROJECT = {
    "_type": "Project",
    "_id": "project",
    "name": "Star Sample",
    "ownedElements": [
        {
            "_type": "UMLModel",
            "_id": "model",
            "_parent": {"$ref": "project"},
            "name": "Architecture",
            "ownedElements": [
                {
                    "_type": "UMLPackage",
                    "_id": "control-zone",
                    "_parent": {"$ref": "model"},
                    "name": "Control Zone",
                    "ownedElements": [
                        {
                            "_type": "UMLNode",
                            "_id": "plc",
                            "_parent": {"$ref": "control-zone"},
                            "name": "PLC",
                            "stereotype": "device",
                        },
                        {
                            "_type": "UMLComponent",
                            "_id": "hmi",
                            "_parent": {"$ref": "control-zone"},
                            "name": "HMI",
                        },
                        {
                            "_type": "UMLComponent",
                            "_id": "gateway",
                            "_parent": {"$ref": "control-zone"},
                            "name": "Gateway",
                            "attributes": [
                                {
                                    "_type": "UMLPort",
                                    "_id": "gateway-port",
                                    "_parent": {"$ref": "gateway"},
                                    "name": "Telemetry Port",
                                }
                            ],
                        },
                    ],
                },
                {
                    "_type": "UMLActor",
                    "_id": "operator",
                    "_parent": {"$ref": "model"},
                    "name": "Operator",
                },
                {
                    "_type": "UMLClass",
                    "_id": "historian",
                    "_parent": {"$ref": "model"},
                    "name": "Historian",
                    "stereotype": "database",
                },
                {
                    "_type": "UMLDependency",
                    "_id": "flow-1",
                    "_parent": {"$ref": "operator"},
                    "name": "HTTPS",
                    "source": {"$ref": "operator"},
                    "target": {"$ref": "hmi"},
                },
                {
                    "_type": "UMLCommunicationPath",
                    "_id": "flow-2",
                    "_parent": {"$ref": "plc"},
                    "name": "OPCUA",
                    "end1": {
                        "_type": "UMLAssociationEnd",
                        "_id": "flow-2-end-1",
                        "_parent": {"$ref": "flow-2"},
                        "reference": {"$ref": "hmi"},
                    },
                    "end2": {
                        "_type": "UMLAssociationEnd",
                        "_id": "flow-2-end-2",
                        "_parent": {"$ref": "flow-2"},
                        "reference": {"$ref": "plc"},
                    },
                },
                {
                    "_type": "UMLDependency",
                    "_id": "flow-3",
                    "_parent": {"$ref": "gateway-port"},
                    "name": "TCP telemetry",
                    "source": {"$ref": "gateway-port"},
                    "target": {"$ref": "historian"},
                },
            ],
        }
    ],
}

STARUML_FRAGMENT = {
    "_type": "DFDDataFlowModel",
    "_id": "fragment",
    "name": "Payment Fragment",
    "ownedElements": [
        {
            "_type": "DFDExternalEntity",
            "_id": "customer",
            "_parent": {"$ref": "fragment"},
            "name": "Customer",
        },
        {
            "_type": "DFDProcess",
            "_id": "billing-api",
            "_parent": {"$ref": "fragment"},
            "name": "Billing API",
        },
        {
            "_type": "DFDDataStore",
            "_id": "ledger",
            "_parent": {"$ref": "fragment"},
            "name": "Ledger",
        },
        {
            "_type": "DFDDataFlow",
            "_id": "fragment-flow-1",
            "_parent": {"$ref": "customer"},
            "name": "HTTPS order",
            "source": {"$ref": "customer"},
            "target": {"$ref": "billing-api"},
        },
        {
            "_type": "DFDDataFlow",
            "_id": "fragment-flow-2",
            "_parent": {"$ref": "billing-api"},
            "name": "store order",
            "source": {"$ref": "billing-api"},
            "target": {"$ref": "ledger"},
        },
    ],
}


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

    def test_parse_architecture_supports_staruml_project_files(self) -> None:
        model = parse_architecture(json.dumps(STARUML_PROJECT), source_name="architecture.mdj")
        assessment = build_assessment(model)
        threagile = build_threagile_yaml_model(model)

        self.assertEqual(model.title, "Star Sample")
        self.assertEqual(len(model.components), 5)
        self.assertEqual(len(model.data_flows), 3)
        self.assertIn("Control Zone", model.boundaries)
        self.assertEqual(model.components["plc"].kind, "device")
        self.assertEqual(model.components["historian"].kind, "database")
        self.assertEqual(model.data_flows[2].source, "gateway")
        self.assertTrue(assessment["coverage"]["has_network_boundary"])
        self.assertEqual(threagile["technical_assets"]["Historian"]["type"], "datastore")
        self.assertEqual(
            threagile["trust_boundaries"]["Control Zone"]["technical_assets_inside"],
            ["gateway", "hmi", "plc"],
        )

    def test_parse_architecture_supports_staruml_fragment_files(self) -> None:
        model = parse_architecture(json.dumps(STARUML_FRAGMENT), source_name="fragment.mfj")

        self.assertEqual(model.title, "Payment Fragment")
        self.assertEqual(len(model.components), 3)
        self.assertEqual(len(model.data_flows), 2)
        self.assertEqual(model.components["customer"].kind, "actor")
        self.assertEqual(model.components["billing_api"].kind, "service")
        self.assertEqual(model.components["ledger"].kind, "database")
        self.assertEqual(model.data_flows[0].protocol, "https")

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

    def test_runner_accepts_staruml_project_and_fragment_files(self) -> None:
        cases = [
            ("examples/test-sample.mdj", json.dumps(STARUML_PROJECT), Path("output/test-runner-mdj"), "Star Sample"),
            ("examples/test-fragment.mfj", json.dumps(STARUML_FRAGMENT), Path("output/test-runner-mfj"), "Payment Fragment"),
        ]

        for filename, contents, output_dir, expected_title in cases:
            with self.subTest(filename=filename):
                input_path = Path(filename)
                input_path.write_text(contents, encoding="utf-8")

                result = run_analysis(input_path, output_dir=output_dir)

                self.assertTrue(result.yaml_path.exists())
                self.assertTrue((output_dir / "threagile.yaml").exists())
                self.assertTrue(result.report_path.exists())
                self.assertIn(expected_title, result.report_path.read_text(encoding="utf-8"))

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
