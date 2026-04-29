# Vehicle Telematics Architecture

## Coverage Summary
- Components discovered: 7
- Data flows discovered: 5
- Trust boundaries discovered: 3

## Missing Or Needs Review
- Core architecture elements were detected. Review protocol, authentication, and asset criticality details next.

## ISO 21434 Focus
- Confirm every vehicle, ECU, gateway, sensor, actuator, backend, and maintenance interface is modelled as an asset or interface.
- Mark safety-relevant and cybersecurity-relevant assets, then review each flow for attack feasibility, impact, and damage scenario inputs.
- Check authenticity, integrity, freshness, and authorization controls for diagnostic, update, and control channels.
- Document where credentials, keys, certificates, and calibration/configuration data are stored and rotated.

## IEC 62443 Focus
- Partition the model into zones and conduits, then verify every conduit has an explicit protocol, authentication expectation, and trust decision.
- Identify industrial control assets such as PLCs, HMIs, engineering workstations, historians, and remote access paths.
- Check account management, least privilege, session control, logging, backup, recovery, and patch/update workflows for each zone.
- Review boundary protections such as firewalls, jump hosts, data diodes, or secure gateways between enterprise, DMZ, and control networks.

## AI Review
Model: `gpt-5.2`

Parsed architecture covers three trust boundaries (Vehicle/Maintenance/Cloud) with key elements for telematics (TGW↔backend, telemetry DB, monitoring) and two in-vehicle OT elements (sensors, brake ECU). Main security-relevant conduits are (1) maintenance laptop→TGW (UDS over TLS) and (2) TGW→OEM backend (HTTPS telemetry/OTA). Several safety- and security-critical details are unspecified or missing for ISO 21434 (cybersecurity concept, update/diagnostics security, key management) and IEC 62443 (explicit zone/conduit enforcement, security services, monitoring coverage).

## Current Status
- Trust boundaries defined at a high level: Vehicle Zone, Maintenance Zone, Cloud Zone; no explicit sub-zones/DMZs or conduits beyond listed data flows.
- Vehicle Zone components: Brake ECU (safety-relevant), Sensor Cluster, Telematics Gateway (network-infrastructure). CAN bus exists between sensors and brake ECU; no explicit secure gateway/firewall shown on vehicle networks.
- Maintenance access is modeled as Technician Laptop → TGW using “UDS over TLS”. No authorization model, credential lifecycle, or physical access assumptions provided.
- Cloud Zone components: OEM Backend API, Telemetry Store (DB), Security Monitoring component. Backend writes to DB; backend sends security events to monitoring. Protocols for backend→DB and backend→monitoring are unspecified (marked unknown).
- TGW ↔ Backend uses HTTPS for telemetry and OTA, but OTA subcomponents (package repository, signer, campaign manager, device identity) are not represented.
- No explicit identity, key management, certificate authority/PKI, or secrets storage components are included despite TLS usage.
- No explicit logging/audit trail, incident response workflows, or alerting outputs are shown beyond a generic “Security Monitoring” sink.
- No explicit external networks (cellular carrier/Internet), edge ingress controls (API gateway/WAF), or cloud network segmentation constructs are modeled.

## Possible Missing Components
- In-vehicle network security controls: a CAN gateway/firewall function (often inside TGW) explicitly mediating traffic between external interfaces and safety ECUs; bus guardian or message filtering.
- In-vehicle IDS/monitoring (e.g., CAN anomaly detection) separate from cloud-only “Security Monitoring”, aligned to IEC 62443 detection requirements.
- Secure diagnostics infrastructure: OEM diagnostic service, access token service, and/or diagnostics authorization server (ISO 21434 diagnostic access control concepts).
- OTA ecosystem components: update package repository, code-signing service, key storage (HSM), campaign/orchestration service, rollback/compatibility metadata, and update audit log.
- Device identity and cryptographic infrastructure: PKI/CA, certificate provisioning, rotation/revocation (CRL/OCSP), and a device attestation service (or equivalent).
- Key/secrets management: cloud KMS/HSM, secrets vault for backend credentials, and secure element/HSM inside TGW (and potentially ECUs) for key protection.
- Cloud ingress/egress controls: API gateway, WAF, DDoS protection, rate limiting, service mesh/mTLS, and network firewalling between backend and DB/monitoring.
- IAM components: identity provider, RBAC/ABAC policy engine, privileged access management for maintenance tools, and audit logging store (IEC 62443-3-3 SR 1.x/2.x style capabilities).
- Telemetry governance: data classification service, consent/privacy management (if personal data), retention/archival system, and data access audit.
- Software supply-chain controls: CI/CD pipeline, artifact registry, SBOM store, vulnerability scanning, and release approval gates (ISO 21434 supporting processes).
- Time sync and trusted time source (NTP with authentication) for reliable logs/forensics across vehicle and cloud.

## Possible Missing Connections
- TGW ↔ Brake ECU / in-vehicle networks: a conduit for diagnostics and/or control (UDS typically targets ECUs via a gateway). Currently only sensors→brake ECU CAN is shown; TGW’s path to brake ECU is not modeled.
- Brake ECU / vehicle events → TGW: operational data, DTCs, and health status often feed telemetry; not represented.
- Maintenance laptop → specific ECUs (via TGW): diagnostic sessions, flashing, parameterization; would affect threat modeling for safety ECUs.
- TGW → Security Monitoring: vehicle-side security events, IDS alerts, authentication failures; currently only backend→monitoring is shown.
- Telemetry DB → monitoring/alerting: database audit logs, anomalous access alerts; currently not represented.
- Backend ↔ IAM/PKI/KMS: backend typically depends on identity/token validation and key retrieval; not represented.
- Backend ↔ OTA repository/signing: separation of concerns (API serving vs. artifact distribution vs. signing) is not modeled; critical for compromise containment.
- Cloud network boundaries: explicit connections/controls between Cloud Zone services (backend, DB, monitoring) such as private subnets, security groups, mTLS/service mesh.
- Technician laptop ↔ OEM backend (optional but common): tool authentication, authorization token retrieval, service bulletin download; not shown but often present.

## Impacts To Investigate
- Safety impact (ISO 21434): If TGW diagnostics/OTA paths can reach Brake ECU, compromise could enable unauthorized reprogramming, parameter changes, or diagnostic session abuse affecting braking behavior.
- Integrity impact: OTA channel compromise (backend or TGW identity) could lead to malicious firmware delivery, persistent compromise, fleet-wide propagation.
- Availability impact: DoS on TGW↔backend link (or backend itself) could disrupt telemetry, remote services, and potentially maintenance operations; vehicle safety fallback expectations are unspecified.
- CAN bus weaknesses: plain CAN between sensors and brake ECU suggests spoofing/injection risk if an attacker gains access to the vehicle network (through TGW, maintenance port, or physical access).
- Maintenance tool risk: Technician laptop as an actor can be a malware entry point; if UDS over TLS terminates at TGW without strong authorization, it may enable broad vehicle access (IEC 62443 external connectivity exposure).
- Cloud data breach: Telemetry DB compromise could expose sensitive operational or personal data; also could be used to infer vehicle location/usage patterns.
- Monitoring gaps: Cloud-only monitoring may miss in-vehicle attacks; delayed detection/response increases dwell time and safety risk.
- Privilege escalation in cloud: Backend API compromise could allow unauthorized DB writes (data poisoning) and suppression/forgery of security events sent to monitoring.
- Unspecified protocols: backend→DB and backend→monitoring being “unknown” increases uncertainty about encryption, authentication, and integrity; MITM and credential replay risks depend on actual deployment.
- Trust boundary ambiguity: “Maintenance Zone” vs “Vehicle Zone” conduit security controls (e.g., physical port security, network segregation) are not defined; impacts depend on access assumptions.

## Suggested Countermeasures
- Model and enforce zones/conduits per IEC 62443: explicitly define conduits between Maintenance↔Vehicle and Vehicle↔Cloud, including security controls (firewalling, protocol break, authentication, rate limiting).
- Secure diagnostics access (ISO 21434): implement strong mutual authentication for technician tools, role-based authorization for diagnostic services, session/time-bound access tokens, and detailed audit logging of all UDS services invoked.
- Constrain TGW as a gateway: add message filtering and allowlisting between external interfaces and in-vehicle networks; ensure safety ECUs (e.g., Brake ECU) are reachable only via tightly controlled services; consider separate diagnostic VLAN/bus.
- Strengthen in-vehicle network protection: where feasible add AUTOSAR SecOC or equivalent message authentication for critical signals; otherwise implement gateway-level plausibility checks, IDS detection, and segmentation to reduce spoofing impact.
- Harden OTA pipeline: separate backend API from update artifact distribution; require cryptographic signing of firmware, verified in TGW/ECU bootloader; store signing keys in HSM; implement rollback protection, version pinning, and staged rollout with monitoring.
- Identity and key management: introduce PKI/CA for device and tool identities, certificate rotation and revocation, and cloud KMS/HSM for server-side keys; ensure TLS is mutual where appropriate (TGW↔backend).
- Cloud security controls (IEC 62443-inspired security services): API gateway/WAF, DDoS protection, least-privilege IAM between backend and DB, network segmentation (private subnets), database encryption in transit and at rest, and secrets management.
- Monitoring/telemetry integrity: send vehicle security logs/events with integrity protection (signing or mTLS + replay protection); correlate backend, DB audit, and vehicle security events; define alerting and incident response triggers.
- Supply-chain security (ISO 21434 supporting processes): CI/CD hardening, SBOM generation, vulnerability scanning, signed artifacts, and controlled release approvals; protect build/signing environment as a high-value asset.
- Operational resilience: define safe degraded modes if cloud connectivity is lost; implement rate limiting and backoff on TGW; ensure maintenance operations have secure offline procedures if needed.
- Clarify and document assumptions: physical access to vehicle ports, technician laptop hardening requirements, expected reachability of TGW to safety ECUs, and required cybersecurity goals for braking-related functions (to drive correct threat severity).

