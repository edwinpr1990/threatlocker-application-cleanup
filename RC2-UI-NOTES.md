# Portal-style dashboard (RC2)

RC1 is preserved as `releases/ThreatLocker-Hash-Cleanup-RC1.zip`. Its file manifest and ZIP checksum were verified. The archive includes source, launch scripts, documentation and tests; runtime journals and customer evidence remain in the original workspace, outside the archive. `app.py` and its original launcher remain unchanged, so the original dashboard is still available on port 8512.

## Open or launch

- RC1: http://127.0.0.1:8512/ — `Start-Dashboard.ps1`
- Portal-style RC2: http://127.0.0.1:8513/ — `Start-PortalDashboard.ps1`

The two entry points share the existing cleanup engine, insights and run journals. Their browser connection settings are separate and credentials stay in session memory. The same application locks continue to protect overlapping local cleanup operations. RC2 is a local tool with portal-inspired styling, not an official ThreatLocker portal page.

## Visual reference and changes

The authenticated ThreatLocker portal was inspected directly. Observed colors included navigation teal `#00425C`, cyan `#00B1D6`, canvas gray `#E9ECEF`, light panels `#F8F9FA`, and coral `#FF605D`. Its buttons had 6px corners and used Proxima Nova with Helvetica/Arial fallbacks. This version uses local Arial/Helvetica fallbacks, without downloading the proprietary font or copying portal assets.

The customer connection panel retains all its inputs, advanced controls, credential handling and disconnect behavior. Presentation changes include a teal workspace header, compact guided steps, portal-like tabs, light cards, stronger metric typography, expandable report controls and application filters, cyan charts, green verified results and cleaner tables. Primary action text uses a darker teal background for legibility. Full names and application IDs remain available in chart hover details and tables; long chart labels preserve their distinguishing suffixes.

The report overview gets more space by collapsing source/filter controls after selection. The preview action appears before charts. Detailed rule explanations and raw records stay available in expandable sections. Saved results, empty states, uncertain responses and live progress retain their original meanings.

## Verification

34 tests pass, including the original suite and equivalent connection, populated-report and simulated running-progress tests for RC2. Browser checks covered the ten-application report, source upload, scope controls, charts, empty results guidance, run history, restoring the Adobe audit, both progress bars and audit download. Layout bounds were checked at the existing browser viewport; no page-wide horizontal overflow or rendering exceptions were found. Responsive CSS is included, but separate mobile-device certification is not claimed.

Visual inspection prompted fixes to header clearance, metric sizing, caption contrast and ambiguous long chart labels. No new deletion was performed for this styling work. RC1's application source was compared to its archived checksum after the work.

Implementation: `portal_app.py` and `portal_theme.py`. Use the new launcher so Streamlit's chart/table theme is light as well as the surrounding interface. Future Streamlit upgrades may require checking the scoped CSS selectors again.
