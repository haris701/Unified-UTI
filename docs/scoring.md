# Finding assessments

UTI does not produce a composite confidence, profile-quality, evidence-reliability, or identity score in new investigation results. These concepts describe different things, and no validated weights or statistical calibration currently justify combining them.

## Profile check outcome

`ProfileCheckOutcome` maps the collector-reported `Finding.profile_check_status` to one of:

| Outcome | Existing status | Meaning |
| --- | --- | --- |
| `positive` | `VALID` | The collector reported a positive profile check. |
| `negative` | `INVALID` | The collector reported a negative profile check. |
| `inconclusive` | `UNVERIFIED` | The collector did not establish a positive or negative result. |
| `error` | `ERROR` | The collector reported an error outcome. |

Each outcome retains the collector name, reported status, and collection timestamp. HTTP status codes remain evidence details; they never override the collector-reported status. A positive outcome does not establish account ownership or identity.

## Record completeness

`RecordCompletenessAssessment` reports the state of each requested record field independently:

- `available`: the field has a value in the normalized record.
- `missing`: the record has no value for the field (for example, no evidence items).
- `unknown`: a record exists, but the field's value is explicitly unknown or not supplied (for example, an evidence type of `unknown`, or an evidence record with no original source URL).

The fields are `evidence`, `evidence_type`, `original_source_url`, `collection_timestamp`, and `source_lineage`. A present collector lineage can be `available` while its underlying data source remains unknown. That uncertainty is reported separately as source independence `unknown`. Completeness describes recorded fields; it does not grade accuracy, relevance, freshness, or reliability.

## Source independence

`FindingAssessment.source_independence` uses declared underlying data-source lineage only:

- `independent`: multiple observations declare distinct underlying source identifiers.
- `dependent`: multiple observations declare the same underlying source identifier.
- `unknown`: there are fewer than two observations, any required source identifier is missing, or lineage does not permit a conclusion.

Collector names alone never establish independence. This assessment does not add points to another score.

## Candidate correlation and identity

`InvestigationResult.correlation_results` remains separate from finding assessments. Correlation groups expose candidate reasons and matched evidence. A username match alone does not create a group; grouping requires a same-profile URL candidate or matching evidence. Even then, a group is not a verified identity assessment, and UTI has no identity score.

Every `FindingAssessment` reports `ownership_status=UNVERIFIED` and `identity_verified=False`. The model also enforces those safeguards on Findings.

## Legacy numeric compatibility

`Finding.confidence`, `Finding.confidence_reasons`, and `uti.scoring.score_finding` remain available for older callers. They retain their historical, uncalibrated weighted heuristic without changed meaning: positive collector status `+0.30`, valid HTTP(S) URL `+0.20`, required metadata `+0.20`, evidence presence `+0.10`, and two explicitly distinct underlying sources `+0.10`, capped at `1.00`. The investigation service does not call that function, and new dashboard-facing summaries must not label or present those legacy values as profile quality, evidence reliability, probability, or identity confidence. `score_finding_legacy` is an explicit alias for migration away from the older name.

## Synthetic examples

- A `Claimed` result with HTTP 200 maps to `positive` because that is the collector's declared result. A Maigret `Unknown` row with HTTP 200 remains `inconclusive`.
- A record with no evidence marks `evidence`, `evidence_type`, and `original_source_url` as `missing`; its required timestamp and collector lineage may still be `available`.
- A record containing evidence with `evidence_type="unknown"` and no source URL marks those fields `unknown`, distinct from missing evidence.
- Two collector observations whose underlying datasets are both undeclared remain `unknown`, even when they report the same profile. Two observations with the same declared dataset are dependent; distinct declared datasets can be classified independent.
- Two findings with only the same queried username and different profile URLs/evidence do not correlate. Correlation results never imply common ownership.

`tests/test_scoring_assessments.py` covers these cases using synthetic data. Existing tests for `score_finding` exercise only the legacy compatibility behavior.
