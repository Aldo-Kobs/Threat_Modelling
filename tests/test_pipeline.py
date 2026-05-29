import builtins
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threatmod_automation.ai_review import AIArchitectureDraft
from threatmod_automation.ai_review import AIReviewResult
from threatmod_automation.ai_review import _architecture_model_from_payload
from threatmod_automation.ai_review import _extract_output_text
from threatmod_automation.ai_review import _extract_github_models_text
from threatmod_automation.guidance import build_assessment
from threatmod_automation.guidance import render_assessment_markdown
from threatmod_automation.models import ArchitectureModel
from threatmod_automation.models import Component
from threatmod_automation.models import DataFlow
from threatmod_automation.parser import parse_architecture
from threatmod_automation.parser import parse_plantuml
from threatmod_automation.runner import run_analysis
from threatmod_automation.threagile import EXCEL_SHEET_NAME_LIMIT
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

    def test_threagile_map_labels_fit_excel_sheet_limit(self) -> None:
        sample = """
@startuml
title This Generated Model Title Is Too Long For Excel
package "Very Long Operational Network Boundary Name" {
  component "Ship Firewall and Remote Access Gateway" as firewall
  component "Safety Monitoring and Alarm Panel" as safety_panel
}
firewall --> safety_panel : Gateway permits tightly controlled vendor diagnostic access to propulsion controller logs
@enduml
"""
        model = parse_plantuml(sample)
        threagile = build_threagile_yaml_model(model)

        self.assertLessEqual(len(threagile["title"]), EXCEL_SHEET_NAME_LIMIT)

        for section_name in ("questions", "data_assets", "technical_assets", "trust_boundaries"):
            with self.subTest(section=section_name):
                self.assertTrue(threagile[section_name])
                for label in threagile[section_name]:
                    self.assertLessEqual(len(label), EXCEL_SHEET_NAME_LIMIT, label)

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

    def test_ai_architecture_payload_is_normalized_before_yaml_generation(self) -> None:
        payload = {
            "title": "AI Drafted Vehicle Gateway",
            "summary": "Drafted from notes.",
            "assumptions": ["Telemetry store persists events."],
            "trust_boundaries": ["Vehicle Zone", "Cloud Zone"],
            "components": [
                {
                    "alias": "Gateway ECU",
                    "name": "Gateway ECU",
                    "kind": "device",
                    "boundaries": ["Vehicle Zone"],
                    "tags": [],
                },
                {
                    "alias": "backend_api",
                    "name": "Backend API",
                    "kind": "cloud",
                    "boundaries": ["Cloud Zone"],
                    "tags": ["it-service"],
                },
            ],
            "data_flows": [
                {
                    "source": "Gateway ECU",
                    "target": "backend_api",
                    "description": "HTTPS telemetry",
                    "protocol": "HTTPS",
                },
                {
                    "source": "backend_api",
                    "target": "Missing Audit Store",
                    "description": "audit events",
                    "protocol": "unknown",
                },
            ],
        }

        model = _architecture_model_from_payload(payload, fallback_title="Fallback")
        threagile = build_threagile_yaml_model(model)

        self.assertEqual(model.title, "AI Drafted Vehicle Gateway")
        self.assertIn("gateway_ecu", model.components)
        self.assertIn("missing_audit_store", model.components)
        self.assertEqual(model.components["missing_audit_store"].tags, ["needs-review"])
        self.assertEqual(model.data_flows[0].protocol, "https")
        self.assertEqual(
            threagile["technical_assets"]["Gateway ECU"]["communication_links"]["Flow 1"]["target"],
            "backend-api",
        )

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

    def test_runner_can_generate_yaml_from_ai_architecture_notes(self) -> None:
        output_dir = Path("output/test-runner-ai-architecture")
        drafted_model = ArchitectureModel(
            title="AI Notes Architecture",
            components={
                "driver": Component(alias="driver", name="Driver", kind="actor", tags=["human-user"]),
                "mobile_app": Component(alias="mobile_app", name="Mobile App", kind="component"),
                "backend": Component(alias="backend", name="Backend API", kind="cloud", boundaries=["Cloud Zone"]),
            },
            data_flows=[
                DataFlow(
                    source="driver",
                    target="mobile_app",
                    direction="-->",
                    description="login",
                    protocol="https",
                ),
                DataFlow(
                    source="mobile_app",
                    target="backend",
                    direction="-->",
                    description="HTTPS API",
                    protocol="https",
                ),
            ],
            boundaries={"Cloud Zone"},
        )
        draft = AIArchitectureDraft(
            enabled=True,
            provider="OpenAI",
            model="gpt-5.2",
            summary="Drafted from text notes.",
            assumptions=["Backend is internet exposed."],
            architecture=drafted_model,
            raw_text="{}",
        )

        with mock.patch("threatmod_automation.runner.draft_architecture_with_openai", return_value=draft):
            result = run_analysis(
                None,
                output_dir=output_dir,
                architecture_notes="Driver uses a mobile app connected to a backend API.",
                ai_architecture=True,
                openai_api_key="test-key",
            )

        self.assertTrue(result.yaml_path.exists())
        self.assertTrue(result.ai_architecture_path.exists())
        self.assertEqual(result.ai_architecture_draft, draft)
        yaml_text = result.yaml_path.read_text(encoding="utf-8")
        self.assertIn("AI Notes Architecture", yaml_text)
        self.assertIn("Backend API", yaml_text)
        draft_text = result.ai_architecture_path.read_text(encoding="utf-8")
        self.assertIn("Drafted from text notes.", draft_text)

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

    def test_runner_can_use_direct_threagile_yaml_input(self) -> None:
        source_path = Path("output/test-direct-yaml-source.yaml")
        output_dir = Path("output/test-runner-direct-yaml")
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_text = "threagile_version: 1.0.0\ntitle: Direct YAML Model\ntechnical_assets: {}\n"
        source_path.write_text(source_text, encoding="utf-8")

        result = run_analysis(
            None,
            output_dir=output_dir,
            yaml_input_path=source_path,
        )

        self.assertEqual(result.yaml_path.read_text(encoding="utf-8"), source_text)
        self.assertEqual((output_dir / "threagile.yaml").read_text(encoding="utf-8"), source_text)
        self.assertTrue(result.report_path.exists())
        self.assertIn("Direct Threagile YAML Input", result.report_path.read_text(encoding="utf-8"))
        self.assertEqual(result.ai_reviews, [])
        self.assertIsNone(result.ai_review_path)

    def test_runner_converts_normalized_architecture_yaml_input(self) -> None:
        source_path = Path("output/test-normalized-architecture-source.yaml")
        output_dir = Path("output/test-runner-normalized-yaml")
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(
            """title: Direct Architecture YAML
summary: Normalized architecture YAML.
assumptions: []
trust_boundaries:
  - Control Zone
components:
  - alias: operator
    name: Operator
    kind: actor
    boundaries:
      - Control Zone
    tags:
      - human-user
  - alias: hmi
    name: HMI
    kind: component
    boundaries:
      - Control Zone
    tags: []
data_flows:
  - source: operator
    target: hmi
    description: HTTPS commands
    protocol: https
""",
            encoding="utf-8",
        )

        result = run_analysis(
            None,
            output_dir=output_dir,
            yaml_input_path=source_path,
        )

        rendered_yaml = result.yaml_path.read_text(encoding="utf-8")
        self.assertIn("technical_assets:", rendered_yaml)
        self.assertIn("trust_boundaries:", rendered_yaml)
        self.assertIn("Control Zone:", rendered_yaml)
        self.assertIn("technical_assets_inside:", rendered_yaml)
        self.assertNotIn("components:", rendered_yaml)
        self.assertIn("Coverage Summary", result.report_path.read_text(encoding="utf-8"))

    def test_runner_shortens_direct_threagile_yaml_labels(self) -> None:
        source_path = Path("output/test-direct-long-labels-source.yaml")
        output_dir = Path("output/test-runner-direct-long-labels")
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(
            """threagile_version: 1.0.0
title: This Direct YAML Model Title Is Too Long For Excel
questions:
  Which flows require authentication, encryption, freshness, and anti-replay controls?: ""
data_assets:
  This data asset label is definitely too long for Excel:
    id: long-data
technical_assets:
  Ship Firewall and Remote Access Gateway:
    id: long-tech
trust_boundaries:
  Very Long Operational Network Boundary Name:
    id: long-boundary
""",
            encoding="utf-8",
        )

        result = run_analysis(
            None,
            output_dir=output_dir,
            yaml_input_path=source_path,
        )

        rendered_yaml = result.yaml_path.read_text(encoding="utf-8")
        self.assertNotIn("This Direct YAML Model Title Is Too Long For Excel", rendered_yaml)
        self.assertNotIn("Which flows require authentication, encryption, freshness, and anti-replay controls?", rendered_yaml)
        self.assertNotIn("This data asset label is definitely too long for Excel:", rendered_yaml)
        self.assertNotIn("Ship Firewall and Remote Access Gateway:", rendered_yaml)
        self.assertNotIn("Very Long Operational Network Boundary Name:", rendered_yaml)
        for line in rendered_yaml.splitlines():
            if line.startswith("title:"):
                _key, _separator, title_value = line.partition(":")
                self.assertLessEqual(len(title_value.strip()), EXCEL_SHEET_NAME_LIMIT, line)
            if line.startswith("  ") and not line.startswith("    "):
                key, separator, _value = line.strip().partition(":")
                if separator:
                    self.assertLessEqual(len(key.strip('"')), EXCEL_SHEET_NAME_LIMIT, line)

    def test_runner_converts_normalized_architecture_yaml_without_pyyaml(self) -> None:
        source_path = Path("output/test-normalized-no-pyyaml-source.yaml")
        output_dir = Path("output/test-runner-normalized-no-pyyaml")
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(
            """title: Direct Architecture YAML
summary: Normalized architecture YAML.
assumptions: []
trust_boundaries:
  - Control Zone
components:
  - alias: operator
    name: Operator
    kind: actor
    boundaries:
      - Control Zone
    tags:
      - human-user
  - alias: hmi
    name: HMI
    kind: component
    boundaries:
      - Control Zone
    tags: []
data_flows:
  - source: operator
    target: hmi
    description: HTTPS commands
    protocol: https
""",
            encoding="utf-8",
        )
        real_import = builtins.__import__

        def block_yaml_import(name, *args, **kwargs):
            if name == "yaml":
                raise ModuleNotFoundError("No module named 'yaml'")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=block_yaml_import):
            result = run_analysis(
                None,
                output_dir=output_dir,
                yaml_input_path=source_path,
            )

        rendered_yaml = result.yaml_path.read_text(encoding="utf-8")
        self.assertIn("technical_assets:", rendered_yaml)
        self.assertIn("trust_boundaries:", rendered_yaml)
        self.assertNotIn("components:", rendered_yaml)

    def test_runner_can_generate_threagile_pdf_via_docker(self) -> None:
        input_path = Path("examples/test-sample.puml")
        input_path.write_text(SAMPLE, encoding="utf-8")
        output_dir = Path("output/test-runner-docker")

        def fake_run(command, capture_output, text, check):
            self.assertIn("docker", command[0])
            self.assertIn("--env", command)
            self.assertIn("HOME=/app/work", command)
            self.assertIn("XDG_CACHE_HOME=/app/work/.cache", command)
            self.assertIn("--mount", command)
            self.assertIn("--model", command)
            self.assertIn("--output", command)
            self.assertIn("/app/work/threagile.yaml", command)
            self.assertTrue((output_dir / ".cache" / "fontconfig").is_dir())
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
