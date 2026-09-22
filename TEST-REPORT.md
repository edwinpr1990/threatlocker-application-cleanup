# Test report — ThreatLocker duplicate cleanup

## UI enhancement follow-up

The deletion-progress follow-up brings the suite to **31 passing tests**. It adds separate accepted/verified bars, per-application progress, pending and reconciliation counts, elapsed execution time and recent record responses. A controlled running-state UI test verifies the progress display without making live API requests; the completed Adobe audit was also inspected in the browser. No additional deletion was required to validate this presentation change.

The subsequent UI update adds guided steps, report metrics, per-application charts, projections, preserved-group explanations, and a run-history summary. **28 current automated tests pass**, including metric checks for repeated rows, shared hashes, identical application names, unavailable counts, and the distinction between HTTP acceptance and verified deletion. The populated report, zero-deletion preview, saved Adobe results and history were checked in the browser. This follow-up changed presentation and read-only summaries; it performed no additional deletions. The live results below describe the earlier cleanup validation.

Executed September 21–22, 2026 (America/New_York / UTC), against the authorized test organization. **PASS: 4,002 automated deletions independently verified**, plus two separate manual portal duplicate deletions. No application definitions or policies were deleted or updated by the cleanup engine.

## Live scope and manifests

Organization: `<test-scope-id>`. All new fixtures were created without policies and remain available for inspection.

| Application | OS | Application ID | Before | After | Automated deletions |
|---|---|---|---:|---:|---:|
| CODEX DUP muc31jrn A | Windows | <test-scope-id> | 772 | 9 | 763 |
| CODEX DUP muc31jrn A | macOS | <test-scope-id> | 771 | 8 | 763 |
| CODEX DUP muc31jrn B | Windows | <test-scope-id> | 2 | 2 | 0 |
| adobe (established imported test app) | Windows | <test-scope-id> | 12,265 | 9,789 | 2,476 |

Counts in the table bracket each automated test. A supplemental macOS manual test later inserted two records and deleted one, so its final count is 9. The Windows manual test occurred before the automated baseline and its surviving record is included in the Windows count of 9.

For each A fixture, four equivalent hash groups had **4, 11, 51, and 701** records before cleanup and **1, 1, 1, and 1** afterward. This means **3, 10, 50, and 700 extra copies** were removed on each OS. The exact lowest numeric ID and all its fields survived in every group. Both 701-record groups traversed multiple pages at search page size 100. `evidence/group-results.json` contains each hash, survivor ID and group count.

Both A applications deliberately have identical names and different IDs/OS. B has a different name and shares a hash with A while containing no duplicates itself. Each application retained its own copy. Unique hash records, custom path rules and key-file ambiguity groups remained unchanged. The same-hash key-file conflict is intentionally preserved in each A application; it is not a cleanup failure.

Adobe's original import preserved all supplied duplicates. Its later dashboard cleanup removed 2,476 redundant IDs from 56 eligible groups, leaving 9,708 hash records and all 81 non-hash records. Independent after-manifest comparison verified exact planned-ID removal, every retained record field unchanged, and an unchanged complete application-metadata response. The other Windows fixture included in that dashboard preview had four stale candidate groups and received zero deletions.

All three disposable fixture application metadata responses were also unchanged. A separate application listing showed zero computer/group/organization policy counts on all three. No policy creation, update or deployment action was performed.

## Live recovery, stale data and idempotency

The fixture controller process was deliberately terminated during execution. A new process reopened the SQLite journal and reconciled the full applications, finding **369 prior target IDs absent**, then completed **1,157 remaining deletions** without selecting new survivors. Final planned and verified sets both contained exactly 1,526 IDs. This was a real process interruption and restart, not an in-memory simulation.

The input included repeated report rows, a nonexistent hash candidate, an exaggerated count on a singleton in B, and explicit application scans to cover report omissions. Candidate counts did not determine deletion counts. A second fixture cleanup preview planned zero further deletions.

After Adobe cleanup, the original stale report was uploaded through the dashboard and all three fixtures were added by ID. The new preview read all four applications and planned **zero deletions**, with 58 skipped groups: 56 now-singleton Adobe candidates and two preserved ambiguous groups. It completed in 5.18 seconds using four metadata requests and 17 record-page requests. The supplemental macOS manual-test survivor was present during this final preview.

## Manual portal and dashboard checks

- Created two disposable same-hash records on Windows and, separately, macOS. Used the portal Application Files search and row deletion, then independently read back one survivor. Captured sanitized search URLs, exact deletion JSON and verification data. The payload's OS was 1 for Windows and 2 for macOS.
- Generated the exact **Applications Containing Same Hash** report from the portal and dashboard. Observed Windows within-application duplicates and omission of the macOS fixture and shared-only B application.
- Used the dashboard to preview and execute Adobe's 2,476 deletions, show verified totals, upload a saved report, preview an idempotent rerun, restore the saved Adobe run through Run history, and trigger an audit JSON download successfully.
- Visually inspected the dashboard. Connection inputs are customer-specific; Authorization is masked. The dashboard exposes survivor IDs, exact planned IDs/statuses, skip reasons, progress and audit exports.

## Timings and response counts

Counts exclude browser CORS OPTIONS requests. Response-time sums overlap under concurrency and must not be interpreted as wall time.

| Stage | Wall time | Metadata GET | Record-page GET | Delete POST | Report POST |
|---|---:|---:|---:|---:|---:|
| Initial fixture preview | 2.78 s | 3 | 20 | 0 | separate |
| Resumed fixture execution | 73.13 s | 6 | 188 | 1,157 | 0 |
| Fixture independent read/report | included below | 3 | 6 | 0 | 1 |
| Adobe dashboard preview (two scoped apps) | 12.96 s | 2 | 16 | 0 | separate |
| Adobe execution and verification | 294.98 s | 4 | 609 | 2,476 | 0 |
| Adobe independent browser/API read | 4.88 s | 1 | 11 | 0 | 0 |
| Final dashboard rerun preview, four apps | 5.18 s | 4 | 17 | 0 | 0 |

The resumed fixture test, including independent comparisons and the rerun preview, took 78.83 seconds. The first interrupted segment's complete HTTP counters were lost with its process; **no full-lifetime request count or uninterrupted wall time is claimed for that run**. The durable journal preserved deletion intentions and outcomes sufficiently for recovery. Later code checkpoints response counters after each wave; counters still describe the latest invocation. Adobe used four workers, fixture execution six. No live rate limit was observed.

## Controlled tests and baseline compatibility

**23 current automated tests pass** (`python -m unittest discover -s tests -v`), covering deterministic selection, differing notes, ambiguous fields, invalid live hashes and unknown flags, cross-application sharing, identical names, idempotency, 700 duplicates, repeated/stale report rows, CSV input, wrong organization, changed/new/missing records, expired credentials, rate-limit failure/resume, uncertain committed deletions, durable dispatch recovery, pause/resume, overlapping local locks, incomplete preview rejection, HTTP success without actual deletion, and initial Streamlit controls.

Failures involving HTTP 401/429, timeout-after-commit and HTTP 200-without-deletion were controlled simulations. They were not forced against the live customer API. Live requests had no unexplained failures; the interruption was intentional. A transient browser locator mismatch during manual searching was resolved by inspecting the actual portal state and did not change deletion scope.

The previous dashboard's **24 existing tests also passed**. `legacy/engine.py` and the original source have identical SHA-256:

`98BB9633952400A31889DD90B42DC7569752C1C0A8A8A7384D9911DD1C5837E7`

The original project was left intact. Its proven transport, pagination, throttling, database and local-lock behavior is reused. Current tests supplement those baseline checks.

## Evidence and limitations

Local evidence is under `evidence/`: `fixtures.json`, `live-before.json`, `live-after.json`, `live-audit.json`, `live-results.json`, `group-results.json`, manual workflow files, `adobe-after.json`, `adobe-audit.json`, `adobe-results.json`, `dashboard-rerun-audit.json`, metadata comparisons and policy-count results. Full baseline bodies and immutable survivor choices are also in the corresponding `runs/*/cleanup.sqlite3` journals. Adobe's preexisting import payloads and verification artifacts remain in `adobe-import/`.

The report omitted macOS fixtures; use explicit application scans. No functioning bulk-delete endpoint, server-side atomic compare/delete, report webhook, or automated report completion trigger was verified. Local locks do not coordinate unrelated remote operators. Preserve an exclusive maintenance window for the affected applications when strong concurrency isolation is required. The implementation was tested up to 12,265 records in one application and retains full per-application manifests in memory; larger deployments need separate capacity measurements. The actual portal CSV download was not retained; CSV parsing was tested with its observed schema, and saved report JSON was uploaded live.

Credentials were used only in memory and excluded from source, journals and saved evidence. Development test services should be stopped after testing; the dashboard remains local to 127.0.0.1.
# September 22 integration validation

Added Application cleanup and Large applications to the preserved portal-style UI. Original `app.py`, `cleanup.py` and `legacy/engine.py` remain byte-identical to the RC2 pre-integration archive.

## New live test

Only disposable fixture **CODEX CONDITION TEST 20260922T042728**, application ID `<test-scope-id>`, was changed.

| Stage | Before | Verified removal | Inserted rules | After | Elapsed |
|---|---:|---:|---:|---:|---:|
| Duplicate hash cleanup | 14 | 3 | 0 | 11 | 2.40 s |
| Hash → conditional rule | 11 | 10 | 1 | 2 | 6.82 s |

Compared full manifests: all duplicate-cleanup survivors unchanged, exact intended hash IDs removed, unrelated unique hash unchanged, application metadata unchanged. A separate read verified the replacement rule. Both new previews planned zero further deletions. Policy association counts were all zero. No failures or uncertain live responses occurred.

Consolidation execution used 24 metadata GETs, 48 paginated file GETs, one insertion POST and 10 deletion POSTs. Full-manifest checks deliberately favor correctness over throughput; large consolidation throughput is not yet benchmarked. The earlier 700-duplicate and Adobe duplicate-cleanup tests remain documented below and were not rerun as part of this integration.

## Controlled tests

`python -m unittest discover -s tests -q`: **47 tests passed**. Browser checks confirmed the new tabs, completed-run progress bars, audit JSON download, filtered health CSV download, and no page-level horizontal overflow at the existing 1685-pixel viewport. The Adobe health CSV independently reported 9,789 live records / 9,708 live hash records versus 12,184 reported hashes. The extra report count is not used as a deletion target.

New unit tests cover original optimizer integration, conservative field checks, no-observation/custom-rule preservation, stale source records, new records, wrong organization, lost write responses after commit, failed insertion blocking deletions and blind retries, interruption/restart, idempotence, multi-observation notes, macOS application blocking, duplicate report rows and invalid/cross-organization large-report data. Streamlit AppTest covers the new populated metrics, review controls and progress bars in addition to the existing UI and hash-engine tests.

## Limits

Conditional rules can broaden application matching. Positive source-observation coverage does not validate unrelated-file collisions or endpoint enforcement. All proposed rules require review. Live consolidation is restricted to supported Windows Program Files candidates; macOS and weaker/ambiguous candidates are preserved. Large-report exact threshold behavior, macOS coverage and refresh latency remain unverified. See `APPLICATION-CLEANUP.md` for recovery and concurrency limits.
