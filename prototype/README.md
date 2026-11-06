# WireProof local TLS feasibility demonstration

Measured run: runs/final-03. Six scenarios, ten repetitions each. Results: 60 trials, 320/320 checks, 90 successful mutual TLS connections, ten expected strict rejections. The separate Python oracle passed all 100 captures and matched all 90 successful selected groups. Zero failed trials in this measured run. Development runs and the independent extracted-package validation run remain under runs/ and are not pooled into the paper. The package-validation run independently reproduced all 60 trials, 320 checks, and 100 oracle capture checks.

## Reproduce

Requirements: Go 1.26 or later with crypto/tls ConnectionState.CurveID and X25519MLKEM768, Python 3 standard library. Measured pins: Go 1.26.1, Python 3.15.2, darwin/arm64. No third-party module, root privileges, packet capture utility, or Docker is required.

~~~sh
./reproduce.sh runs/reproduced-01
~~~

The destination must not exist. The script builds, runs tests, executes ten repetitions, replays the exact schedules, checks the independent oracle, and emits JSON, CSV, and LaTeX rows. For the three public CLI commands:

~~~sh
go build -o wireproof-demo .
./wireproof-demo run -out runs/new-study -repetitions 10
./wireproof-demo replay -dir runs/new-study
./wireproof-demo summarize -dir runs/new-study
python3 oracle.py runs/new-study
~~~

Replay checks the recomputed ledger decisions against each trial's recorded expected scenario decisions. It does not open a new TLS connection. The oracle reads preserved server-to-client TCP bytes independently of ledger decisions. Summarize reports actual original trial outcomes, including failed checks and errors, rather than replacing them with replay results. An oracle mismatch is an investigation failure. The process exits nonzero on scenario failures while preserving completed logs.

## Mechanism and trust

The client represents checkout and the two separately launched payment processes represent old and new deployments. Both payment processes execute the same binary, with distinct configuration hashes and certificate identities. The old process permits X25519 and the new process permits X25519MLKEM768. The normal client permits both. A strict hybrid client accepts the new process and cannot connect to the old process.

Test-only P-256 certificates authenticate both directions in TLS 1.3. URI identities distinguish checkout, old payment, and new payment. The trusted launcher checks executable and configuration digests returned by each child and records PID, address, identity, and digests. Request metadata attributes checkout.pay. The TLS exporter supplies an original handshake identifier shared by client and server. A transparent relay logs both byte streams and socket mappings. Go endpoint telemetry records the group, while oracle.py independently parses the TLS ServerHello key_share extension. TLS resumption and early data are disabled.

Observation records are Ed25519-signed by the trusted harness observer. They preserve connection, handshake, operation, identities, digests, source time, and original negotiation epoch. Appraisal events reference these facts under a policy and assignment epoch. Appraisal history is exported separately with epoch, policy, mode, evidence references, population, and assessment cut. Assessment history is append-only. Current eligibility changes and late corrections are separate arrays in replay.json. CurrentStatus inside a historical assessment is the eligibility snapshot at issuance, not a mutable field. The current state is reconstructed by replaying later Changes.

This is trusted process-launch binding, not hardware attestation or Kubernetes workload discovery. The independent parser validates the negotiated group only. Authenticated peer identity uses Go's verified certificate chains. This is narrower than the planned certificate-chain and CertificateVerify algorithm observer. Harness control events, registry completeness, clock, process launch records, and endpoint keys are trusted. The prototype does not implement distributed barriers, arbitrary policies, a general rolling window, autonomous timeout/expiry, signature receipts, or actuation beyond strict TLS endpoint configuration. Freshness is checked when an assessment executes, with a two-second limit. Every trial's registry retains every discovered connection until the trial ends.

## Evidence and claim scopes

A reported assessment retains every connection with any accepted observation and requires key-establishment and authentication evidence for the same connection and handshake. A discovered connection with no accepted observation is explicitly unassessed. The full-population request additionally requires the exact trusted registry and a barrier. Reassignment cannot clear the registry or rewrite original facts. The fixed scenarios test unappraised conflicts and replay after an active epoch is invalidated. Additional event orders and reused observation IDs have unresolved behavior, listed in the root README.

The strong version-aware baseline receives the identical events, identities, policies, assignments, freshness rules, and invalidation schedule. It checks the same connection-level evidence and reported populations and retains inspectable history. WireProof additionally validates operation/artifact/configuration binding and supports complete-population assessment. Baseline complete requests are marked unsupported and do not count as erroneous decisions. Both methods agree on the ordinary reported-scope violations in the six scenarios. No performance superiority is claimed. Enforcement options and exceptions are controlled equally in the planned mesh protocol, not implemented as a general local policy engine.

## Preserved files

- manifest.json: platform, Go version, executable digest, observer public key, identity bindings.
- launch.json and server logs: actual child endpoints and negotiation telemetry.
- events.jsonl: exact signed observations and trusted control-event order, original times, liveness, appraisals, barriers, and cuts.
- trial.json: intended checks, actual outcomes, capture references, errors, timing.
- replay.json: both appraisal and verdict histories, eligibility changes, rejected evidence, and corrections.
- client/server .bin and sockets.json: raw TCP evidence and mapping.
- summary.json/csv/tex and oracle.json: observed counts, manuscript table rows, independent parser results.
- source-sha256.json: final source hashes, measured environment, binary hash. evidence-sha256.json hashes the measured evidence files.

The test-pki keys are ephemeral demonstration credentials, not production credentials. The signing private key and CA private key are not persisted. Retained leaf keys are generated test material. The distributed source package omits those leaf private keys and the compiled binary. Reproduction generates fresh certificates and therefore fresh hashes and timestamps.

## Timing and limitations

The stale case deliberately holds evidence for 50 ms. The measured interval runs from the later connection response to its first population discovery, which makes both methods pending. For final-03 it ranges from 50.155 to 51.156 ms, median 51.135 ms. It includes scheduling and instrumentation. These are descriptive local measurements, not mesh latency or a comparative speedup. Ten fixed repetitions do not justify the planned 59-independent-trial confidence statement.

No Kubernetes/Istio experiment or new mechanized proof was executed by this demonstration.
