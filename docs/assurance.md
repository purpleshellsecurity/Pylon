# Detection assurance and release evidence

Pylon distinguishes **generation**, **execution**, and **behavioral evidence**.
The presence of a query in a report is not proof that it detects the intended
behavior. Neither successful KQL parsing nor successful live execution alone
establishes detection quality.

## What the existing gates prove

| Gate | Supported claim | Does not prove |
| --- | --- | --- |
| Static and contract checks | No recognized structure/contract defect | KQL parses or catches an attack |
| Offline KQL engine | Query ran under tested engine/schema conditions | The intended behavior matches |
| Live operation comparison | Measured count relationship on sampled workspace/window | Event-level precision or threshold correctness |
| Offline labeled fixture | Attack/benign sets behaved as reported in the tested engine | Sentinel scheduling, rule deployment, or alert delivery |
| Deployed alert exercise (external) | A rule produced the expected alert in its deployment | All future behaviors are covered |

## Grading modes

`pylon design grade --fixtures fixtures/` is exploratory. It fails on
unreadable fixtures, engine errors, and false positives against benign sets.
An empty or silent result can still be inconclusive; it is **not** a pass.

`pylon design grade --fixtures fixtures/ --strict` is a **behavioral release
gate**. Every supplied fixture must produce an attack match and no benign
match; unreadable, silent, or erroneous cases fail. The caller must still
confirm that the fixtures cover the planned detections and represent their
intended behavior. Passing an incomplete set does not certify full coverage.

## Release-review contract (EngineeringStandard AES-24–29, AES-36–40)

Before claiming a detection is behaviorally validated, attach:

1. Its source query hash, target operation, table, schema, and tested engine.
2. The fixture identity, labeling rationale, positive and negative sets.
3. Test command, environment/version, timestamp, and observed exit code.
4. Any live verification separately, with workspace, window, widened query
   status, and inconclusive verdicts retained.
5. Explicit limitations: no ground truth, aggregated detection, skipped
   provider, or missing deployed alert exercise.

Code tests, live workspace queries and deployed alert exercises are distinct
evidence types. No skipped check can be recorded as passing. Do not claim
`deployment validated` from `design grade` or from a query returning hits.

The template in `docs/release-assurance-template.md` is a human-reviewed
release record, not a claim that these tests have already been run.
