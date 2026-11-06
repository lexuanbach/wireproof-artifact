# WireProof artifact

Local feasibility demonstration for **WireProof: Verifiable Post-Quantum Cryptography Migration for Service Ecosystems**.

WireProof links connection evidence to operations and service instances, records the population an assessment covers, and separates historical assessments from current eligibility. This repository contains the Go TLS prototype, an independent Python handshake parser, captured evidence, and the planned research protocols.

The [supplementary reproduction notes](supplement.pdf) document the measured run, reproduction commands, evidence navigation, and all four unresolved cases. The source is [supplement.tex](supplement.tex).

## Quick start

Requires Go 1.26 or later and Python 3. The prototype uses only their standard libraries and local loopback connections.

```sh
bash prototype/reproduce.sh runs/reproduced-01
```

The output path is relative to `prototype/` and must not exist. The command runs the existing tests, executes six scenarios ten times each, replays the schedules, checks captured handshakes independently, and generates JSON, CSV, and LaTeX summaries. See [prototype instructions](prototype/README.md) for the `run`, `replay`, and `summarize` interfaces.

## Recorded evidence

The paper's measured run is [final-03](prototype/runs/final-03). It records 60 trials, 320 successful scenario checks, 90 successful mutual TLS connections, and ten expected strict rejections. The independent parser checks all 100 captures and agrees on all 90 successful negotiated groups. Earlier development runs and independent package-validation runs are preserved separately, including their actual failures. Their counts are not pooled into the paper.

The demonstration uses real hybrid and classical TLS negotiations. Trusted process-launch records provide artifact binding. It does not establish hardware attestation, Kubernetes discovery, Istio enforcement, distributed completeness, or a new mechanized proof. Ten repetitions of fixed scenarios do not establish the planned independent-trial confidence bound.

## Current implementation limits

The fixed demonstration results do not establish correctness for every asynchronous event sequence. Four behaviors remain unresolved in this source snapshot:

- Invalidation received before its assignment can be forgotten.
- An assessment with a wrong policy can revoke eligibility and then allow confirmation under the same epoch.
- Conflicting signed observations that reuse an identifier can leave the original fact usable.
- A late historical correction does not itself withdraw current eligibility until another assessment occurs.

The contract sketch describes intended semantics. The implementation and the preserved measurements are a feasibility prototype, not a completed implementation of all those semantics. General rolling windows, autonomous expiry, complete authentication-algorithm observation, and mesh integration remain planned.

## Repository contents

- [prototype/](prototype/) contains source, tests, reproduction commands, and raw runs.
- [REPRODUCE.md](REPRODUCE.md) covers local and pinned prior-work reproduction.
- [CONTRACT-SKETCH.md](CONTRACT-SKETCH.md) and [COUNTEREXAMPLE-TRACES.md](COUNTEREXAMPLE-TRACES.md) specify intended semantics and illustrative traces.
- [EVALUATION.md](EVALUATION.md), [PROTOCOL-WP2.md](PROTOCOL-WP2.md), and [ROADMAP.md](ROADMAP.md) describe planned studies and extensions.
- [evidence/](evidence/) records claim provenance and software pins.

Raw captures, signed observations, public test certificates, and source hashes are retained. Generated executables, caches, and private test keys are excluded. Fresh reproduction creates new certificates, timestamps, and hashes.
