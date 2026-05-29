# Marine Ship Dynamic Architecture Set

These Threagile model YAML files describe the same vessel under different operating states. They are Docker-ready Threagile examples, not normalized architecture drafts.

- `marine_ship_architecture.yaml`: baseline connected vessel with bridge, machinery, ship IT, satcom, shore operations, and cloud telemetry.
- `marine_ship_bridge_navigation.yaml`: at-sea bridge navigation, sensor fusion, ECDIS, autopilot, steering, and voyage recording.
- `marine_ship_engine_control.yaml`: machinery control, power management, safety alarms, engineering workstation, and historian logging.
- `marine_ship_remote_maintenance.yaml`: remote vendor support with approvals, brokered access, maintenance DMZ, jump host, and audit logging.
- `marine_ship_port_cargo_operations.yaml`: in-port cargo exchange, ballast and stability workflows, customs integration, and reefer monitoring.
- `marine_ship_emergency_mode.yaml`: degraded local control, emergency network isolation, radio communications, and incident evidence capture.

Each YAML follows the structure of `threagile-example-model.yaml`:

- `data_assets`, `technical_assets`, and `trust_boundaries` are maps, not lists.
- `communication_links` point to technical asset IDs in the same file.
- data asset references use IDs declared under `data_assets`.
- trust boundary memberships use technical asset IDs declared under `technical_assets`.

Example Docker-oriented workflow:

```bash
PYTHONPATH=src python -m threatmod_automation.cli --yaml-input examples/marine_ship_architecture.yaml --output-dir output/marine_ship_baseline --threagile-docker
```

You can also run Threagile directly against any of these example YAML files because they are already in Threagile model format.

Fontconfig cache note:

The project CLI sets `HOME=/app/work`, `XDG_CACHE_HOME=/app/work/.cache`, creates `.cache/fontconfig`, and mounts a writable output directory before running Docker. That avoids the repeated `Fontconfig error: No writable cache directories` messages.

If you bypass the CLI and run Docker manually, use a writable mounted work directory and pass those environment variables to the container.

