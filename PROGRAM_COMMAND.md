# PROGRAM_COMMAND.md

Authority Source:
Veristio Program Command (VPC)

Class Implemented:
Rack

Delegated Authority:
- Provide physical/edge execution substrate, capacity, and measured constraints for Veristio systems.
- Report hardware state via Signal-compatible telemetry when authorized.

Explicit Prohibitions:
- This repository will never define policy, intent, priorities, or authority (Program Command only).
- This repository will never self-authorize builds, deployments, or actions (Field executes; Control gates).
- This repository will never override Control gates or bypass halts.
- This repository will never suppress or manipulate evidence (Signal preserves truth).
- This repository will never present human guidance as authority (Advantage explains).

Upstream Dependencies:
- Program Command (scope)
- Signal (telemetry/evidence interfaces) [when applicable]
- Control (constraint enforcement surfaces) [when applicable]

Downstream Consumers:
- Field (execution environment consuming Rack capacity)
- Signal (hardware truth feeds)
- NOC (operational awareness)
- Advantage (human-facing summaries)

Lifecycle Status:
ACTIVE

Release Intent:
INCLUDED in V1.0.0
