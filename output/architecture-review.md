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
