# WireProof contract, observation, and appraisal model

Revised 6 November 2026. The general design is planned. The executable local subset and its limits are documented in prototype/README.md. No mechanized WireProof proof is claimed.

## Contract and authority

K names contract ID/version, source, destinations, obligations, issuer-authorization relation, observation-window length W, separate freshness limits Delta, policy version, and response. An obligation names evidence kind, operation, and allowed values. Kinds include key establishment, peer authentication, and application signatures. The general authentication obligation includes policy-approved certificate-chain and CertificateVerify algorithms in required directions. Local auth means mutual X.509 identity verification only.

Each activation has a unique assignment epoch. An epoch cannot be reused after invalidation. A policy change requires a new epoch. A fallback is a distinct contract, never a relabeling of a violation. Only authorized build attestors supply capabilities, deployment authorities supply assignments, and authorized observers/verifiers supply runtime facts. Issuer authority is scoped by kind and subject.

## Three data objects

1. Observation: original connection/handshake or signature ID, operation, endpoints, artifact/configuration hashes, negotiated values, issuer, source timestamps, original negotiation epoch, and evidence references. Facts are immutable. Duplicate delivery does not refresh timestamps. Conflicts remain visible.
2. Appraisal: assignment epoch, policy, references to original evidence and dependencies, population, and assessment cut. Reassignment references an old handshake without rewriting its identity, artifact, or negotiation history. Separate recent liveness is required for a still-open connection.
3. Verdict history/current status: immutable assessment records identify population, mode, cut, evidence, omissions, and outcome. Current eligibility can change after issuance. A late contradiction of the original claim appends a correction. It never overwrites history.

A record for one operation cannot discharge another. Ambiguous multiplexed requests, missing fields, unauthorized issuers, wrong bindings, and absent dependencies cannot support confirmation. Capability/configuration evidence supplies preconditions, not proof of runtime behavior.

## Population and time

For one transport interaction define common reported U before checking individual obligations. Retain every connection with any accepted transport report, including partial evidence. Join all applicable obligations on the same connection and original handshake ID. A connection with key-establishment evidence but no authentication remains pending, rather than disappearing in an intersection. Discovered connections with no accepted records are explicitly unassessed. An assessment cannot choose a smaller population to conceal accepted partial or conflicting evidence.

Sat_obs requires a nonempty U, current assignment, supporting capabilities, authorized fresh checks, a causally consistent evidence cut, and every applicable obligation satisfied for every member. Missing or undecidable evidence prevents satisfaction. A known forbidden value defeats it.

P enumerates all connections overlapping [tau-W,tau], including closed or draining connections that overlap. Complete mode requires U=P, a sealed manifest, every required record, no stream sequence gaps, and barriers acknowledging all events and dependencies through the assessment cut. Registry completeness is an external assumption, tested against an independent connection log. Missing streams or unbounded delay prevents complete confirmation. Signature P is the explicitly selected sample, not all signatures.

W selects the observation population. Delta separately bounds liveness age and appraisal age. Historical handshake facts retain their original time. Retransmission is neither liveness verification nor reappraisal. The prototype uses the entire trial as its population window, a two-second liveness limit at assessment, and trusted harness barriers. It retains all known connections across epochs. It does not implement general window expiration or distributed sequence closure.

## Eligibility and asynchronous invariants

Pending becomes confirmed when the required predicate holds, or blocked on known violation or unmet evidence at timeout. Confirmed becomes revoked after affected assignment/policy/deployment invalidation or violation. Expiry or inability to obtain sufficient evidence for the current assessment makes eligibility pending. A complete-mode request never silently downgrades. Blocked/revoked epochs require a new authorized assignment. The prototype tests expiry at assessment and does not implement an autonomous timeout service.

Later events can make a historically correct statement insufficient for current use. Late evidence about an original member at or before the original cut can instead show that the original claim was wrong, requiring an appended correction. A sealed historical cut does not lose completeness because the next cut is incomplete.

P1 is planned soundness across every permitted asynchronous sequence of delayed, duplicated, conflicting, reordered, expired, and reassigned events, under authentic observations and correct bindings. P2 is permanent ineligibility of an invalidated epoch, despite replay, with conditional recovery under a fresh epoch. Component delay bounds are assumptions required for any physical-time exposure bound. Eventual delivery alone gives no finite deadline. Trusted observers and adapters are not covered by a deployed-code refinement proof.

P3 is an optional conjunction rule. Its substantive requirements are complete TLS-hop enumeration, compatible snapshot cuts, and trusted termination. Missing external evidence leaves the path unknown. No universal ranking of hybrid and pure PQC is imposed.

If actuator isolation fails, the mesh remains an observation-and-verdict core. Only enforcement experiments move to the local testbed. Attribution failure is separately reported as an unmet mesh gate.
