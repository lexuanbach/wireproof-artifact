# WireProof evaluation protocol

Status: revised 6 November 2026. The held-out mesh study below is planned. A separate measured local feasibility study is recorded in prototype/runs/final-03 and is not pooled with future sampled trials. This protocol specifies the planned evaluation.

## Freeze and sampling

At M3 define the fault taxonomy, population construction, independent oracle procedure, initial sampling frame, exclusions, and metrics. Tune on development cases. At M18 freeze controller configuration, baseline adapters, software pins, randomization distributions, analysis code, and the held-out manifest before inspecting held-out labels. Report post-freeze deviations.

For each fault class, define a distribution over topology, deployed versions, traffic, fault location, and timing. Draw one scenario per reset deployment. Document independence and the represented testbed population. Seeds and resets prevent carryover but do not themselves establish independence.

One fixed decision case per draw is used for the Bernoulli false-confirmation analysis. Multiple timed observations within a deployment belong to the same block for stale-assurance and operational analysis. When shared infrastructure or repeated templates undermine independence, report deployment-block uncertainty and empirical counts. Do not use the 59-independent-trial assertion.

## Ground truth

- Key establishment: independent packet capture and parser, including PSK-only versus fresh-key-share resumption. Missing original-handshake linkage remains unknown. Disable early data in core runs.
- Authentication: testbed session-key export and a separate handshake dissector. Shared trust in endpoint keys is declared. Check all required directions and chain/CertificateVerify fields.
- Signatures: a second implementation checks the predeclared receipt sample, operation, key, message, and context.
- Population: an independent registry/capture audit establishes which connections overlap the window, including closed and draining old-version connections.
- Injection logs establish intended mutations, not successful effects. Capture/configuration verification establishes the actual effect.

Count ineffective injections and exclude them from the intended-fault denominator. Replacement follows the predeclared next random draw, retaining both original and replacement. Oracle disagreement receives independent adjudication blinded to method outcome. Unresolved disagreement, empty populations, and undecodable mandatory fields remain unknown. Report unknowns and exclusions, never silently discard them.

## Two time-aligned analyses

### Decision correctness

A case names contract, assignment epoch, policy, assurance mode, population, and event-time cut. Apply the independent oracle to that same population and cut. Noncompliant means at least one known violation. Compliant requires complete labels for every required field and no violation. Everything else is unknown.

Compare the new verdict with this label. In reported mode, the population is the reported set and that limitation is explicit. In complete mode, independently check the manifest against the actual population. An omitted violating connection is a false confirmation, not an unknown silently removed from the denominator.

A late-arriving violating record for a connection already in the claimed snapshot indicates an erroneous earlier complete confirmation. It is not reclassified as a subsequent event.

### Stale assurance and exposure

At predeclared fixed times, inspect verdicts still presented as usable. An initially correct verdict remaining usable after a later violation is stale assurance. Report prevalence, duration, and request-weighted noncompliant exposure. Do not hide this merely because initial confirmation was correct.

Separate event origin, detection, ingestion, processing, enforcement, and connection close times. Measure clock offset/error and report timing intervals when it matters. For settled cases, inject at least D_det + D_del + D_proc before the evaluation cut. Transient trials deliberately sample throughout that period. A partition or missed deadline is an outcome, not an excluded outlier.

## Outcomes

| Outcome | Denominator or interpretation |
| --- | --- |
| New-decision false confirmation | Newly confirmed / independently noncompliant decision cases |
| Confirmation coverage | Newly confirmed / independently compliant decision cases |
| Unknowns and false blocks | Full verdict-by-label matrix, with mode and population |
| Stale assurance | Fraction of usable verdict-time samples stale, plus duration |
| Request-weighted exposure | Noncompliant requests during stale or ineffective-enforcement intervals, with total traffic denominator |
| C_wire | Compliant decidable connections / all decidable connections in the window, with unknown share |
| C_decl | Prior declared-label metric, not the same population as C_wire |
| Attribution and closure | Correct, wrong, and unknown mappings, complete-cut availability |
| Actuation | Isolated, shared, and observation-only edge/traffic shares, collateral effects |
| Availability and recovery | Blocked requests, recovery time, unresolved recoveries |
| Cost | CPU, memory, storage, handshake latency, observer/controller overhead |

## Principal comparator and secondary baselines

Use equivalent topology, traffic, hardware, and available telemetry. Pin implementations and disclose every adapter or reimplementation.

1. Static CBOM checker: capability-level component control.
2. Configuration-only policy checker: assigned settings.
3. Prior QuantumTrustKG selector at d13e3b624ed6eb88441faa77299d3dc5705d4a0c: metadata-level control.
4. Runtime observer without artifact/identity provenance: isolates binding.
5. Istio strict PQC compliance policy on documented proxy/ztunnel mTLS, upstream/downstream TLS, and xDS paths. Pin the release and settings before execution. https://istio.io/latest/news/releases/1.27.x/announcing-1.27/change-notes/ establishes support. Exceptions never count as hybrid satisfaction. The executed local strict endpoint comparison is not an Istio experiment.
6. Principal comparator: a runtime policy monitor with the same group telemetry, workload identities, policy/version keys, expiration, deployment-event invalidation, enforcement options, and exceptions. WireProof adds operation/artifact binding, evidence dependencies, population accounting, and inspectable verdict history. Unsupported complete-population claims are capability gaps, not automatically decision errors. Compare equivalent populations/cuts/modes. The local comparator shares reported-scope guards and history logging conservatively.

Predeclare expected fault visibility. Measure availability cost as well as security. Linkerd supplies an operational capability reference, not a claim that one metric endpoint reproduces WireProof.

Ablations remove binding, freshness, closure, and invalidation. Exercise delayed/duplicated records, wrong operations, unauthorized issuers, ambiguous multiplexing, rolling updates, mixed groups, and policy epochs.

## Statistical interpretation

For each class, zero errors in 59 independent sampled noncompliant cases yields one-sided 95% upper bound 1 - 0.05^(1/59), approximately 4.95%. This assumes independent draws from the declared distribution. It is not simultaneous confidence over all classes or a guarantee on every deployment. Any future simultaneous claim needs a preregistered adjustment and revised sample size.

WP4 targets zero observed false confirmations and at least 90% observed compliant-case coverage, with separate counts and intervals. A 90% point estimate does not imply a lower confidence limit above 90%. M6's attribution target means at least 950 of 1,000 correct mappings, zero wrong mappings, and at most 50 explicit unknowns.

WP2 uses its separate family protocol. Record hardware, dependency pins, seeds, blocked tasks, failures, exclusions, and adjudications. No confidence bound substitutes for its assumptions.

## Local study already executed

See prototype/README.md and prototype/runs/final-03. Six fixed scenarios each ran ten times, with 320/320 checks, 90 successful TLS connections, and ten expected strict rejections. Raw ServerHello parsing matched endpoint telemetry for all successful handshakes. The injected 50 ms delay is reported descriptively. The measured population is the entire local trial. Trusted process launch and request metadata supply binding. No Kubernetes discovery, full authentication-algorithm oracle, distributed closure, general expiry scheduler, or automated migration was evaluated. No 59-trial confidence bound applies.

Both engines receive the same replay schedule. Baseline complete-mode outputs are unsupported, excluded from error denominators, and separately counted. Matched reported-scope decisions agree for ordinary violations. Tests of binding and event-sequence invariants provide local functional checks, not a proof or an empirical general superiority claim. Historical records remain immutable when eligibility changes. Source hashes, evidence hashes, failures, and raw outcome counts are retained.

At M6, non-isolatable enforcement leaves the Kubernetes/Istio core as an observation-and-verdict system. Enforcement experiments move to the local testbed. Failed attribution remains an unmet mesh gate, with uncertainty reported rather than guessed mappings.
