# Threat analysis

`uti.identity.analysis.analyze_threats` creates explainable indicators from source-attributed attributes and their supporting evidence. It does not label users malicious, infer compromise, or calculate a universal risk or identity score.

## Implemented rules

- Public identity exposure: explicitly source-reported name, alias, biography, organization, or coarse location.
- Public contact exposure: an explicitly published email or phone value.
- Digital footprint: retrieved biography, website/domain, linked profile, or profile image evidence.
- Domain and organization association: explicit source links/metadata only.
- Developer information and public technology disclosure: explicit skills/technology keywords found in profile metadata, JSON-LD, or visible profile text.
- Professional information exposure: explicit job-title or affiliation fields.
- Evidence quality issue: collection diagnostics.

All generated severities are `INFORMATIONAL`, with an explicit explanation that public visibility alone does not establish harm. Each indicator retains evidence snippets, source references, exact related attributes, related profile findings when canonical source URLs match, defensive review actions, and limitations. Duplicate observations are retained as provenance but repeated values do not inflate attack-surface counts.

Potential impersonation, profile inconsistency, source reliability, and high-severity rules are declared concepts but are not generated. The current code has no validated rules or source reliability dataset to support them. Two differing names, jobs, or profiles are not enough to infer inconsistency; shared values do not establish common ownership.
