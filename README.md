# ThreatLocker Application Cleanup

A local Python/Streamlit dashboard for duplicate hash cleanup, reviewed conditional-rule consolidation, application health reports, and resumable audit history. It keeps one equivalent hash record **per organization and application ID**. The same hash remains present in every application that contains it.

## Launch

Python 3.13 was used for testing. From this directory in PowerShell:

```powershell
.\Start-PortalDashboard.ps1
```

The launcher creates a virtual environment, installs `requirements.txt`, and opens a server at **http://127.0.0.1:8513**. Open that address in your browser. Alternatively:

```powershell
python -m pip install -r requirements.txt
python -m streamlit run portal_app.py --server.address 127.0.0.1 --server.port 8513 --browser.gatherUsageStats false
```

## Use

1. Enter the customer label, organization UUID, API instance letter, UserInstance letter, and complete Authorization header value. Credentials remain in process/session memory. The application does not extract credentials from other browsers; development testing used the explicitly authorized existing portal session.
2. Generate **Applications Containing Same Hash**, or upload its CSV/JSON data. Required columns are `OrganizationId`, `ApplicationId`, and `Hash`; `Name` and `Count` are optional hints. JSON may be an array or an object containing `data`. Repeated rows are collapsed. A report containing another organization is rejected as a whole.
3. Choose application IDs and operating systems. Enter additional application UUIDs, one per line, to scan applications omitted by the report. **The report omitted macOS in live testing.** Explicit scans are necessary for those applications.
4. Build the dry-run preview. Review application IDs, hash groups, survivor IDs, skip reasons, and deletion counts on **Execution and audit**. Preview reads current records; report counts never authorize deletion by themselves.
5. Type the displayed `DELETE <count>` phrase and execute. Counts distinguish accepted requests from independently verified absence. Download audit JSON and per-record CSV after completion or a stop.
6. Use **Run history** to load a previous run. Reconcile current records first, then authorize the updated remaining count. Replace expired credentials in the sidebar before resuming. Disconnect clears session credentials after active requests finish.

This is a local, single-operator tool. It is not a hosted customer portal with user authentication or tenant access controls. Customer records and notes in local manifests/audits remain sensitive operational data; keep them with that customer's workspace. Organization and API instance scope are rechecked when a run resumes.

## Reading the dashboard

The report overview shows selected applications, application/hash candidate groups, distinct hashes, and estimated extra records. The application chart ranks the top 15 by known report counts. Missing or invalid counts are marked unknown and the estimate is shown as a lower bound. Shared hashes are described separately; they are never treated as a global deletion group. OS filters apply when building the live preview because the report has no OS field.

The execution view uses the saved live baseline and journal to show per-application planned and verified deletions, expected remaining records, exact retained IDs and reasons for preserving groups. Expected totals are projections, not fresh counts. The guided Discover → Review → Verify workflow explains the next action; advanced settings and detailed records are expandable. History shows status and remaining work, and lists only runs matching the organization and API instance.

During deletion, two progress bars distinguish accepted requests from independently verified absence. The panel refreshes every two seconds and shows queued/pending records, outcomes needing reconciliation, elapsed execution time, the age of the last deletion response, the ten latest record responses, and progress for each application. A running indicator means the local task is active; it does not prove the API is responding. Verification can remain at zero while requests complete because absence is confirmed by full application reads. Multiple deletions can appear between refreshes.

## Cleanup contract

- Only ordinary hash-only rules with empty path, certificate, process, installer and size constraints, and no key-file flag, are eligible. Conflicting original fields, hash indicators, rule types, or unknown populated fields cause the entire group to be preserved and flagged.
- The lowest numeric `applicationFileId` survives. Names are display labels, never identifiers. Notes can differ without changing matching semantics: original record bodies and notes are archived in SQLite, and the survivor is not modified.
- A complete baseline manifest is recorded before any deletion. Full manifests are compared before execution/recovery and after execution. Targeted hash searches revalidate each group before every wave of at most 32 deletions.
- Each deletion intention is committed to SQLite before the HTTP request. A successful HTTP response does not establish deletion. A missing ID is counted only after an independent full read; surviving and unrelated records must have exactly the original returned fields.
- Writes are never automatically retried. A timeout, rate limit, or uncertain response stops new submissions and drains in-flight requests. Reconciliation determines which IDs actually disappeared before an explicit resume can retry remaining IDs.
- Reads retry bounded transient failures. HTTP 429 reduces request concurrency and observes a shared cooldown. Full scans continue through an empty terminal page, rejecting repeated IDs, overlapping pages, and cross-application records.
- Local OS locks coordinate dashboard and CLI processes on the same machine. Survivor IDs remain fixed on resume. New, missing, or modified records stop the existing plan. There is no verified server-side transaction or compare-and-delete API: unrelated portal operators on another machine can still race an in-flight request. Coordinate maintenance for the affected applications.

Only application-file deletion is issued by this engine. It does not update application definitions, attach/deploy policies, or remove application definitions.

## Run history and recovery

`runs/<run>/cleanup.sqlite3` uses WAL and synchronous FULL. It stores scope, full application metadata, baseline record bodies, immutable survivor choices, intended deletion IDs, response statuses, and events. Keep the directory intact for recovery. An interrupted or incomplete preview cannot execute; create a new preview. An interrupted execution can resume using the original run.

`Planned` means no dispatch was journaled; `Dispatched` means the outcome may be unknown; `Accepted` means HTTP success only; `Uncertain` means a failed/unknown response; `StillPresent` means reconciliation found the record; `VerifiedAbsent` means a full read confirmed it missing. Dispatched-but-unsent work is conservatively reconciled after interruption.

Request counters count received HTTP responses; network attempts without a response are represented by their uncertain outcome rather than a response count. Execution timings/counters describe the most recent execution/reconciliation invocation, not the lifetime total across process restarts. Metrics are checkpointed after each wave. Audit events retain the per-record response history.

## CLI and external scheduling

There is no verified report webhook or completion trigger. The observed mechanism is an on-demand report API call. The CLI supports external scheduling of **previews**; no schedule was installed. `--fetch-report` loads the report, `--report` reads an export, and repeated `--application` adds explicit scans. Scope fetched reports to the intended organization and inspect the preview before enabling execution.

```powershell
python cli.py --org <organization-uuid> --instance d --user-instance D --report report.csv --run-dir runs\review-001
python cli.py --org <organization-uuid> --instance d --user-instance D --resume --run-dir runs\review-001 --reconcile-only
python cli.py --org <organization-uuid> --instance d --user-instance D --resume --run-dir runs\review-001 --execute --confirm-count 42
```

The CLI prompts without echo for Authorization, or reads `TL_AUTHORIZATION` supplied by your runtime/secret manager. Never put a token in a command argument, source file, or report. Fresh scheduled previews should use unique run directories. An OS filter is available in the dashboard; the CLI validates Windows/macOS metadata and allows explicit application selection.

## Files and validation

- `app.py`: dashboard; `cleanup.py`: reusable engine; `cli.py`: command-line workflow.
- `legacy/engine.py`: unchanged copy of the previous working engine. Its transport, validation settings, pagination, SQLite connection and OS locks are reused. The new executor retains bounded submission while reusing worker threads/connections across waves. The original project remains intact.
- `API-FINDINGS.md`: actual report, search, deletion and OS observations.
- `TEST-REPORT.md`: live results, timings, failure simulations and limitations.
- `evidence/`, `runs/`, and `adobe-import/`: local test evidence and audit records, excluded from Git. No authorization headers are stored in them.
- `live_test_controller.py`: development-only fixture harness, not needed to run the dashboard. It accepts credentials in memory on localhost and restricts its tests to recorded fixture IDs.

```powershell
python -m unittest discover -s tests -v
```

The current implementation keeps per-application manifests in memory during comparison. This run validated up to 12,265 records in one application; it does not establish performance for millions of records or an unrestricted multi-customer service.
# Application cleanup integration

The portal-style dashboard now includes **Application cleanup** (reviewed hash-to-conditional-rule consolidation) and **Large applications** (reported sizes, search, CSV export and live count verification). See [APPLICATION-CLEANUP.md](APPLICATION-CLEANUP.md) for the guided workflow, recovery behavior and current Windows-only consolidation limits. Launch the existing `Start-PortalDashboard.ps1` and open http://127.0.0.1:8513. RC1 is preserved; the pre-integration portal UI is additionally archived as RC2.
