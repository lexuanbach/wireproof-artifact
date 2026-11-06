# WireProof artifact roadmap

Status: revised 6 November 2026. The local TLS prototype is now measured in prototype/runs/final-03. Mesh deployment and the programme below remain planned.

| Month | Deliverable | Dependency and gate |
| --- | --- | --- |
| M3 | Threat model, schema, sampling frame, analysis questions, software-pin plan | Versioned protocol |
| M6 | Executable ledger, counterexample traces, telemetry/actuation feasibility | At least 950 of 1,000 correct mappings, zero wrong, remainder unknown. If actuation isolation fails, retain mesh observation/verdict core and move only enforcement experiments to local TLS. Attribution failure remains an unmet mesh gate |
| M12 | Manual signature fixtures, binding prototype, P1 target, family feasibility | Core independent of agent migration, decide 50-family target or empirical fallback |
| M18 | Single-cluster observer/ledger, frozen held-out configuration | Separate assurance modes and trace conformance |
| M22 | Invalidation, recovery suite, P2 target | Report timing exceedances, second cluster only after core gates |
| M24 | Core release and reproduction attempt | Schemas, traces, pins, scripts, claim map. Optional branches only if feasible |

Planning allocation in person-months: WP1 14, WP2 12, WP3 10, WP4 16, WP5 12, WP6 8, total 72. These are requested resources, not confirmed employment or funding.

Prior evidence: QuantumTrustKG at https://github.com/lexuanbach/quantumtrustkg, commit d13e3b624ed6eb88441faa77299d3dc5705d4a0c, Apache-2.0. The new repository, license, and DOI have not been created. Do not describe the prior artifact as the WireProof release.
