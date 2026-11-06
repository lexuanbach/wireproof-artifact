# WP2: Independent signature tests and conditional agent admission

Status: planned design, revised 5 November 2026. No tasks or results have been generated.

## Core dependency and task

The runtime core needs manually validated ML-DSA-65 receipt fixtures and an independent verifier. It does not depend on an agent or calibrated gate. Produce the manual fixtures first.

The optional study migrates application signing in Java and Go while preserving legitimate functionality. TLS, public-key infrastructure, hardware security modules, and key encapsulation are outside this task. Freeze library versions, signature mode, context handling, and encodings in the run manifest.

## Families and effort

A family groups related repositories and forks. Assign exactly two predeclared tasks per family. The target is 100 tasks in 50 families: 10 development, 20 calibration, 20 held out. Reserve development families before score/model design. Randomly split the remaining sampled families without outcome-based stratification.

A 60-task, 30-family pilot uses 10/10/10 families and reports empirical results only. If even that is infeasible, release manual fixtures and available tasks with counts, without a calibrated claim. The M12 feasibility gate checks licenses, revisions, eligibility, and family relationships.

WP2 has a 12-person-month planning allocation. Manual fixtures and cross-library verification receive priority. The core M18 release proceeds even if the agent study is dropped.

## Frozen pipeline

1. Define the sampling frame, two-task construction, language mixture, exclusions, and licensing.
2. Develop scores, prompts, models, retries, and public admission tests on development families only.
3. Freeze these before final candidate generation for calibration/test families. Select one candidate per task under the same predeclared retry rule. Record failed attempts and cost.
4. Run mandatory independent admission checks outside the agent workspace. Protect tests, monitors, dependency allowlists, and contracts from candidate changes.
5. Obtain hidden adjudication labels from cross-library tests, negative tests, context/encoding checks, and expert resolution. These extend beyond admission checks, avoiding a circular oracle. Calibration labels may set the threshold. Test labels may not.
6. Freeze the threshold before inspecting held-out outcomes. Count unresolved hidden labels as loss for an admitted task.

Use independently implemented libraries. Check wrong keys, changed messages, context mismatches, serialization, and monitor bypass. Record common dependencies or shared vectors as limitations.

## Exact risk target

At threshold u, admission requires frozen hard checks and score s > u, where s is the frozen patch evaluation score. Ties are rejected. Family loss L_i(u) is 1 if any admitted task is defective or unresolved under hidden adjudication, and 0 otherwise. Two fixed tasks per family make the event comparable.

Select the least restrictive threshold satisfying

    (sum_i L_i(u) + 1) / (n + 1) <= 0.10

over predeclared score breakpoints and a reject-all endpoint. Raising u removes tasks, so loss is non-increasing. Strict admission makes the step function right-continuous. If no useful threshold qualifies, report reject-all rather than a successful useful gate.

Conformal risk control concerns expected loss for a new exchangeable family. It is not the defective fraction among admitted patches or a per-patch guarantee. Exchangeability requires calibration and target families, task construction, candidate generation, and labeling to follow the same sampling process. Random splitting does not establish transfer to arbitrary future repositories. Unsupported assumptions, changed scoring, or insufficient families trigger empirical-only reporting.

At n = 20 the inequality permits at most one calibration-family loss. Zero losses in 20 independent held-out families gives only a 13.91% one-sided 95% upper bound. Calibration validity and estimation precision are distinct.

## Utility and reporting

Report family/task counts, admitted valid tasks, admitted defective tasks, unresolved labels, rejected valid tasks, abstentions, compute including retries/failures, and human time. Useful acceptance is valid admitted tasks divided by valid tasks, with raw counts. Reject-all has zero useful acceptance.

Compare paired methods by repository-family resampling, not by treating sibling tasks as independent. Publish exclusions, leakage checks, and oracle disagreements. No completed guarantee is claimed before assumptions and results are checked.


Revision 6 November 2026: runtime core is organized around attribution, coverage, and verdict lifecycle. The local final-03 TLS demonstration is measured. Automated migration and composition remain optional and have no new results. The WP2 family protocol is unchanged. See ROADMAP.md and EVALUATION.md for the programme and planned study.
