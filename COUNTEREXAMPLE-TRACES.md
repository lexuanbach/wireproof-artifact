# Ledger traces and validation status

Revised 6 November 2026. The local subset below is now exercised by prototype/ledger_test.go and the six scenarios. Distributed, signature, and actuation cases remain WP1/WP4 requirements. No trace is a mechanized proof.

| Case | Events | Required outcome |
| --- | --- | --- |
| Delayed violation | c1 is compliant, c2 violates but its report is delayed, manifest includes both | Reported mode covers c1 only. Complete mode waits for closure, then blocks. Eventual reporting is insufficient. |
| Duplicate delivery | Resend c1's record and sequence number | Deduplicate without refreshing observation time or increasing coverage. |
| Wrong operation | Receipt verifies, refund-signing record absent | Refund remains unknown, regardless of shared artifact. |
| Wrong issuer | Build attestor signs a runtime assertion | Reject it despite a valid signature. |
| Rolling replacement | v1 stops accepting traffic, an old connection drains while v2 starts | Preserve v1 binding and old connection in the window after reassignment. |
| Old epoch | A satisfying epoch-1 record arrives after epoch 2 begins | Do not resurrect epoch 1 or reuse it as an epoch-2 assignment. Reappraisal binds the original subject explicitly. |
| Multiplexing | Operation cannot be attributed to the connection | Unknown, never borrowed evidence from an unrelated operation. |
| Missing barrier | Observer or policy stream partitions | No complete cut, then block at timeout if completeness is required. |
| Stale verdict | A violation occurs after a correct decision but before detection | Preserve the historical decision label, count stale assurance and request exposure. |
| Omitted old violation | A violating connection is discovered inside a claimed complete historical window | Count an erroneous original complete confirmation, not just a later lifecycle event. |
| Inconsistent cut | Observation references an absent assignment or binding | Reject snapshot consistency even when algorithms are allowed. |
| Recovery | New epoch, repair, fresh evidence, necessary barriers | Confirm only the specified mode. Recovery needs delivery and fair processing. |
| Shared actuator | Changing a cluster affects two contracts | Mark non-isolation and report collateral effects. |
| Composition | Two trusted terminating hops require hybrid groups | Check their conjunction at a shared cut without ranking pure above hybrid. |

## Execution map

| Concern | Executed evidence | Remaining scope |
| --- | --- | --- |
| Split ke/auth and missing auth | TestSplitConnectionEvidence, TestMissingAuthentication | Full auth algorithm observer |
| Partial population omission | TestPartialSubjectCannotDisappear | Distributed registry completeness |
| Wrong binding/issuer/signature | TestWrongBinding with five subtests | Kubernetes discovery and multiplexing |
| Duplicate/stale liveness | TestDuplicateDoesNotRefresh | Autonomous expiration scheduler |
| Missing barrier | TestMissingBarrier, delayed scenario | Distributed sequence barriers |
| Policy or handshake conflict | TestPolicyMismatch, TestConflictingHandshake | Arbitrary policy language |
| Immutable history and reappraisal | TestHistoryAndReappraisal, TestAppraisalPreservesScopeAndCut, reassignment scenario | General rolling windows |
| Late historical contradiction | TestLateCorrectionIsAppendOnly | Independent historical-population oracle |
| Invalidated epoch replay | TestHistoryAndReappraisal, TestDuplicateAssignmentCannotReset | Mechanized P2 |
| Omitted conflict / future fact | TestUnappraisedConflictCannotHide, TestFutureEvidenceCannotConfirm | Mechanized P1 |
| Strong baseline unsupported full mode | TestBaselineCompleteUnsupported | Mesh baseline implementation |
| Real fallback, rollout, delay, stale assurance | final-03 trials and independent raw-group oracle | Kubernetes/Istio |
| Shared actuator and cross-organization composition | Not executed | Planned isolation tests and P3 applicability |

The prototype retains all discovered trial connections, so it cannot silently remove a draining subject on reassignment. Local historical correction tests append records without changing earlier assessments.
