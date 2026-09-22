# Guided UI update — September 22, 2026

## Implemented

- Search applications by name and Windows/macOS, with full IDs to distinguish identical names. Search pages are validated for organization, OS, custom-application status and repeated IDs. Reported sizes are labeled; unavailable counts are not invented.
- Select → Analyze → Review → Execute → Results indicators.
- Before/after panels for duplicate removal and conditional-rule consolidation, plus expandable rule-to-source record mapping.
- Overview with direct workflow buttons, connection-scoped report metrics, and explicit report freshness limits.
- Combined, searchable run history for both engines, with CSV export and read-only loading.
- Active-operation status and stop control above the tab navigation.
- Changing the selected application blocks execution of a different saved conditional-rule preview until a new preview is built.

## Automated verification

`python -m unittest discover -s tests -q`: **56 tests passed**.

This includes actual engine executions driven through Streamlit AppTest using controlled API doubles: hash preview → typed confirmation → deletion → verified survivors → zero-deletion repeat preview; conditional preview → scope acknowledgment → typed confirmation → replacement insertion → source deletion → verified result/download controls.

Application search tests cover pagination, identical names with distinct IDs, cross-organization results, wrong OS, built-in records, repeated IDs, and connection changes. History tests cover both workflow types and organization isolation. Existing tests cover uncertain responses, restart, preservation and cleanup idempotence.

The new UI execution tests exposed a Windows file-sharing race: a concurrent journal read could deny atomic replacement. The fix serializes in-process journal access and retries only transient local rename failures. API writes are never replayed by this retry. A dedicated failure simulation and both UI execution tests pass with the fix.

## Fresh live verification — pending authentication

Browser checks passed for overview-to-cleanup navigation, saved-run before/after panels, rule expansion controls, combined history rendering and CSV download. The exported history contains both workflow types. The page has no horizontal overflow at the existing 1685-pixel viewport. An actual expired-session application search showed a handled HTTP 440 error and made no changes.

The current portal session expired before fresh test fixtures could be created. The portal displays its login screen and the prior authorization was rejected. No new live cleanup was attempted with the expired connection. The user has been asked to sign in again; fresh disposable-fixture tests remain pending.

The earlier live test results in `evidence/consolidation-live/results.json` are historical evidence, not fresh validation of this update. They verified three duplicate deletions, ten covered-hash deletions, one inserted conditional rule, preservation and zero-change reruns.

## Limits

No finite suite proves all possible customer data or portal behavior. Conditional-rule live application retains the existing Windows Program Files restrictions and review requirements. Report counts may lag live state. The application picker does not load every application's records merely to display sizes; live counts remain an explicit action.
