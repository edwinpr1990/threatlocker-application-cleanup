# Application cleanup and large-application reporting

The guided UI now starts with Overview and offers searchable application pickers in both workflows, before/after comparisons, per-rule source records, shared run history, and a status panel across tabs. See [GUIDED-UI-TEST-REPORT.md](GUIDED-UI-TEST-REPORT.md) for verification of this update and the current live-test status.

The portal dashboard at http://127.0.0.1:8513 now includes **Application cleanup** and **Large applications**. Launch with `./Start-PortalDashboard.ps1`. The existing customer connection panel and duplicate-hash workflow remain available.

## Guided workflow

1. Load **Applications with more than a Thousand Hashes** in Large applications, or upload its CSV/JSON export. Search by application name or ID and download the health table.
2. Select an application and verify its current counts. Reported counts may lag current records; the chart deliberately labels them as reported hashes.
3. In Application cleanup, enter the application ID and build a preview. Conservative is the default; Balanced and Aggressive affect suggestions, but do not bypass independent safety checks.
4. Inspect every proposed condition and the covered/preserved record IDs. Download the JSON review and proposed-rules CSV.
5. Confirm the broader matching scope and type the displayed APPLY count. The engine inserts replacement rules, reads them back, then deletes only reviewed source hashes. Progress distinguishes verified rules from verified deletions.
6. Download the audit. Interrupted runs can be loaded in the same tab with the original organization/instance credentials. Credentials are never saved in run files.

No application cloning, merging of separate applications, policy reassignment, or policy deployment is included.

## Reused code and behavior

`legacy/optimizer_logic.py` is the original Python rule engine from the user's `threatlocker-unified-react-node-dashboard-full-fixed-v4.zip`, `python_engines/logic.py`. It is retained unchanged. The new adapter uses its parsing, profiles and candidate generation, then independently checks coverage and constrains suggestion depth. The existing `cleanup.py` and `legacy/engine.py` provide authentication, pagination, rate-limit handling, metadata validation and shared application locks.

The adapter preserves custom/key-file rules, unrecognized semantics, records with multiple Path observations, and hashes without sufficient observations. Only Windows Program Files paths with a product-level anchor and another exact identity condition are eligible for live application. Unsupported syntax and weaker candidates remain review-only. macOS consolidation is not enabled; existing Windows/macOS duplicate deletion is unchanged.

Each rule is matched against parsed source observations with all populated conditions required. This is **positive observation coverage**, not a proof that the replacement has identical security scope. Conditional rules intentionally cover additional possible files; there is no Unified Audit collision replay or endpoint execution validation in this version. Review is required for all candidates. Certificate candidates that do not match the parsed observation exactly are excluded rather than inferred as equivalent.

## Journaling and recovery

`runs/<run>/consolidation.json` contains application metadata, the full original manifest, exact proposed rules, source IDs, write dispatch states, verified replacement records, deletion statuses and responses. Writes use a flushed temporary file and atomic replacement. Before/after every write the engine reconciles complete manifests. It stops for new records, changed metadata/fields, missing unsubmitted records, missing replacement rules, or reappearing verified-deleted IDs. Shared OS locks prevent overlap with duplicate cleanup on the same machine.

An uncertain insertion is never replayed automatically. A uniquely matching inserted rule can be recovered by its run marker and fields; a missing/ambiguous insertion blocks deletion and requires review. A submitted deletion still present can be retried only after reconciliation. Missing replacement rules after partial execution stop the run. There is no automatic rollback; original manifests remain available, and restoring deleted records would assign new IDs.

The first implementation prioritizes full-manifest verification and serial writes. It is not benchmarked for 100,000-record consolidation and may be expensive at that size. Report loading itself does not enumerate application records. Live count verification is explicit. Remote portal/API writers cannot share the local lock; ThreatLocker provides no verified atomic compare-and-delete operation, so a race between a final read and a write remains possible.

## UI research applied

- [Carbon data table guidance](https://v10.carbondesignsystem.com/components/data-table/usage/): visible application identities, searchable tables and context-specific actions.
- [Nielsen Norman Group: progressive disclosure](https://www.nngroup.com/articles/progressive-disclosure/): metrics and next actions first, source manifests and connection details in expandable sections.
- [Nielsen Norman Group: confirmation dialogs](https://www.nngroup.com/articles/confirmation-dialog/): specific consequences and exact record counts instead of a generic confirmation.
- [ThreatLocker: managing application definitions](https://threatlocker.kb.help/managing-application-definitions/) and [creating custom rules](https://threatlocker.kb.help/creating-custom-rules/): multiple populated parameters act together, and conditional rules require more judgment than duplicate removal.

## Preserved releases

`releases/ThreatLocker-Hash-Cleanup-RC1.zip` remains unchanged. The preferred portal UI before this integration is saved in `releases/ThreatLocker-Hash-Cleanup-RC2.zip`, with a SHA-256 manifest for every included file. Runtime journals, source application data and credentials are excluded.
