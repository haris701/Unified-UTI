# Attack surface assessment

`uti.identity.attack_surface.assess_attack_surface` summarizes the selected investigation using deduplicated profile candidates, URL verification outcomes, distinct normalized identity values, candidate correlations, and explainable threat indicators.

It reports discovered and eligible profile URL counts, profile-specific accessible responses, inconclusive and failed/skipped URLs, distinct identity attributes, public contact values, developer/technology values, professional details, websites/domains, correlations, and threat indicators. Category summaries include identity, contact, developer, professional, digital footprint, website/domain, organization, profile inconsistency, and evidence-quality categories.

The assessment produces a narrative and evidence-linked defensive actions. **It does not produce a numeric score.** Current evidence is not calibrated to a defensible common risk scale, and no probability of compromise is calculated. If public-page evidence is insufficient, overall status is `inconclusive`. Counts are descriptive; profile count and platform category are not treated as risk.

Limitations state that profile presence does not establish ownership, generic pages are inconclusive, safety/cap restrictions may leave candidates unchecked, and no breach feeds, private datasets, credential checks, or external identity APIs are included.
