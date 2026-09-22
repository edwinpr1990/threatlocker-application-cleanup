# ThreatLocker API observations — 2026-09-21/22

Observed in the authenticated portal, version 4.8.15.13325, API instance `d`. Authorization values are intentionally omitted. These are observed portal endpoints, not a claim of a stable public API contract.

## Report

Exact name: **Applications Containing Same Hash**. Report ID: `54cccc49-3d2e-473c-ac25-c943fd58a0f7`.

The Predefined Reports screen exposes category/report selection and **Generate**. Its actual request was:

```http
POST /portalApi/Report/ReportGetDynamicData
```

```json
{
  "reportId": "54cccc49-3d2e-473c-ac25-c943fd58a0f7",
  "startDate": "2026-09-21T04:00:00.000Z",
  "endDate": "2026-09-22T04:00:00.000Z",
  "data": "",
  "offsetInMinutes": -240,
  "valid": true,
  "includeChildOrganizations": false,
  "options": []
}
```

Response: `{ "data": [...], "columns": [...] }`. Fields are **Count, Hash, ApplicationId, Name, OrganizationId**. OS is absent and must be read from application metadata. No additional report-specific input filters were exposed. Result-grid search, per-column filters and column visibility are available. Excel, PDF and CSV export buttons were present. Clicking CSV caused lazy export-library loading, with no separate report-export API request observed; export appears client-side. The generated JSON response is supported directly for repeatable ingestion. CSV ingestion supports the displayed column names; no downloaded portal CSV file was retained in this test.

The report showed the Adobe app's 56 within-application duplicate groups and the Windows fixture's four eligible duplicate groups. It omitted the macOS fixture, including its 701-copy group. The differently named Windows B app had a single copy of a hash shared with both A apps and was omitted. Thus observed rows identify within-application Windows duplicates; **the report is not a complete cross-OS inventory and should not be interpreted as an instruction to remove cross-application sharing**. A key-file ambiguity was deliberately preserved by the engine regardless of report coverage.

The implementation can invoke this report on demand, accepts its ID as a dashboard setting, and supports uploaded CSV/JSON. Its API invocation uses the current UTC day and offset 0; the portal's observed local-day body is shown above. No verified scheduled callback/webhook was discovered. The CLI is the integration point for an external scheduler.

## Context and validation

Base URL: `https://portalapi.<instance>.threatlocker.com/portalApi`. The connection carries `Authorization`, `ManagedOrganizationId`, `OverrideManagedOrganizationId`, and `UserInstance`; the original transport also supplies `UseNewSearch`, Origin and Referer. Instance and organization are customer inputs, not fixed engine constants.

`GET /Application/ApplicationGetById?applicationId=<uuid>` establishes actual application ID, owner organization, name, OS, and non-built-in status before a plan is created. Windows is OS 1 and macOS OS 2. macOS file GET records were observed with `osType: 0`; the deletion body must carry the validated application's OS 2. Do not infer application OS from a file row alone.

## Manual search and deletion, revalidated for Windows and macOS

Portal sequence: application → **Application Files** → hash in **Search** → search button → one row's trash button → **Yes**. Both manual tests used disposable fixture rules, two matching records before and one after.

```http
GET /ApplicationFile/ApplicationFileGetByApplicationId
  ?applicationId=<uuid>&searchText=<hash>
  &pageNumber=1&pageSize=25&hashOnly=false
  &isCustomRule=false&showTotalCount=false
POST /ApplicationFile/ApplicationFileDeleteById
```

POST carries the returned file record, including `applicationFileId`, all matching fields, notes, original fields, min/max sizes and flags; the portal adds application ID/name, organization ID, and the actual application OS. Windows manual target ID was `4937527572`; macOS manual target ID was `51290782`. Responses alone were not treated as proof: new GETs established exactly one remaining matching ID.

Sanitized evidence: `evidence/manual-workflow.json`, `manual-verification.json`, `manual-mac-workflow.json`, and `manual-mac-verification.json`. The macOS supplemental test occurred after the main fixture cleanup; it added two records and removed one, increasing that fixture's final count from 8 to 9.

## Pagination and execution

The engine uses page size 100 for hash searches, a configurable full-scan size, and an empty terminal page. A 701-record group therefore spans eight nonempty pages at size 100 plus an empty page. It rejects repeated/overlapping IDs instead of assuming the returned page size or count proves completeness. Both OS 700-extra-copy groups completed with exact before/after ID comparison.

One POST is issued per redundant record. A reusable worker pool bounds concurrent requests; every wave contains at most 32 intended IDs and is preceded by hash-group revalidation. Full manifests establish final absence independently of hash search and verify every retained/unrelated record's fields.

No working bulk-delete endpoint has been established. The earlier `PUT /Application/ApplicationUpdateById` using `removeApplicationFileIds` returned HTTP 200 without deleting records. That unsuccessful shortcut is not used or retried here. Controlled tests also ensure a deletion HTTP 200 with unchanged records is never counted as verified deletion.

## Concurrency and uncertainty

Same-machine application locks prevent overlapping local cleanup processes. Deterministic lowest-ID survivors and fixed journals prevent different survivor choices on resume. External changes detected in full reconciliation or before the next wave stop the plan. There is no observed atomic server snapshot or conditional delete, so a concurrent remote edit during an in-flight request cannot be ruled out. Report data is always treated as stale-capable candidate data.

GET/read-only report retries are bounded. Deletion failures stop new submissions, reconcile, and require explicit resume; no blind POST replay. Live tests encountered no HTTP 429 or expired credentials. Those paths were covered by controlled tests rather than claiming live fault induction.
# September 22: conditional-rule cleanup and large application report

- Exact report: **Applications with more than a Thousand Hashes**, ID `4277aabc-94fe-4b3e-a336-9af0128e116a`.
- Observed portal request: `POST /Report/ReportGetDynamicData`, same body shape as the duplicate report, `includeChildOrganizations: false`, `options: []`, empty `data`, timezone offset -240 in the portal. Dashboard uses UTC day boundaries with offset 0.
- Columns: ApplicationId (Guid), Name (String), OrganizationId (Guid), Count of Hashes (Int32). No OS field or configurable threshold was exposed in the observed report controls. The threshold's exact boundary and macOS coverage have not been independently fixture-tested.
- Live retrieval returned 38 applications and 2,363,271 reported hash records. These are reported counts, not removable duplicates. Adobe still reported 12,184 hashes after the earlier verified deletion run; the report must not drive writes without current record validation.
- Conditional rule insertion verified with `POST /ApplicationFile/ApplicationFileInsert`, `hash: ''`, `isHashOnly: false`, `keyFile: false`, `fullPath` and `processPath` populated, empty `cert`/`installedBy`, organization/application IDs and Windows osType 1. The inserted rule was read back before deleting covered hashes through the existing verified delete endpoint.
- Disposable fixture `<test-scope-id>`: 14 records → 11 after duplicate deletion → 2 after consolidation (one conditional rule and one unrelated hash). Computer/group/organization policy counts remained zero. No policy deployment.
- Full original and final manifests, exact insert/delete audit, timings and rerun checks are under `evidence/consolidation-live/`. This validates API record operations, not ThreatLocker agent execution behavior or negative-collision equivalence.
