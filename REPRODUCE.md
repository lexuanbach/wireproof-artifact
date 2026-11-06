# Reproducing WireProof and its prior evidence

The local demonstration is reproduced with prototype/reproduce.sh from the project root or ./reproduce.sh inside that directory. See prototype/README.md for the three commands and preserved final-03 evidence. It uses real local TLS and does not deploy a mesh.

The prior findings table values come from the public QuantumTrustKG artifact.

```bash
git clone https://github.com/lexuanbach/quantumtrustkg
cd quantumtrustkg
git checkout d13e3b624ed6eb88441faa77299d3dc5705d4a0c
pip install -r requirements.txt
python3 scripts/check-claims.py --markdown        # checks every value against stored results
make -C implementation baseline-compare            # prior findings row 1 (H2 and Alibaba scales)
make -C implementation staleness-sweep             # prior findings row 2
make -C implementation pq-handshake                # optional upstream check, not reported in the prior findings table
make -C implementation wire-tls                    # optional upstream check, not reported in the prior findings table
make -C formal/coq                                 # prior findings row 3 (Coq/Rocq 9.1.1)
```

Mapping from manuscript values to upstream claim IDs is in `evidence/CLAIMS.csv`. Handshake timings depend on the host and will differ from the reported medians.

This revision does not claim to rerun the upstream experiments. The prior findings table has three metadata-level rows. The separate local results table reports WireProof final-03. Mesh results remain planned in EVALUATION.md. The local repetitions do not justify the planned 59-case bound.
