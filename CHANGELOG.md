# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-06-10

Complete restructure of the 2,300-line monolith into the **CyberEssentialsAudit**
module, with full Cyber Essentials (Danzell v3.3) control coverage.

### Added
- **Summary tab**: RAG verdict (Pass / Fail / Manual / Unknown) for every CE
  sub-requirement, with reason, evidence and a link to the detail tab.
- **Malware protection check** (previously not audited): Defender AV policies
  across intents/baselines, settings catalog, classic profiles, compliance
  policies and hybrid GPO; real-time protection, cloud protection, PUA and
  signature-cadence signals; macOS AV manual-evidence row.
- **Security update management check** (previously not audited - Danzell
  auto-fail territory): update rings evaluated against the 14-day requirement
  (deferral + deadline + grace, pause detection), feature/driver/expedite
  profiles, macOS software-update policies, hybrid GPO update policies.
- **End-of-life OS detection**: per-device support status and support-end date
  (Windows client incl. 25H2, Windows Server, macOS current-and-two-prior),
  edition-aware (Home/Pro vs Enterprise lifecycle dates); EOL devices fail
  CE-SU-02.
- **Scope tab** (Danzell scope declaration) and **Run info tab** (tool version,
  operator, scopes granted, every API error - auditable provenance).
- **Unknown verdict semantics**: every failed Graph read is journaled; checks
  touching a failed area report Unknown instead of a silent pass/fail.
- **App-only authentication** (`-AuthMode App` with certificate) for
  unattended/scheduled runs; meaningful exit codes in `-NoMenu` launcher mode.
- **JSON output** (`Export-CeReport -Format Json|Both`) for pipelines/SIEM.
- New user-access checks: MFA registration coverage, stale/leaver accounts,
  guest review, device-locking compliance.
- Pester 5 test suite with fixtures; PSScriptAnalyzer ruleset; GitHub Actions
  CI (lint + test on PowerShell 5.1 and 7, release packaging on tags).
- Transcript logging next to the report.

### Fixed (accuracy bugs from the 2026-06-10 review)
- **B1** Formula-injection neutraliser never fired for `=` `+` `-` `@`
  (string-vs-char `-contains` comparison).
- **B2** MFA headline counted disabled and report-only CA policies as
  enforcing; only `enabled` policies count now.
- **B3** Intune-enrolled servers were misclassified as Windows 10/11
  workstations (Server 2019/2022 builds missing from the map; SKU ignored).
- **B4** No unsupported/EOL OS detection; build map was missing Windows 11
  25H2.
- **B5** `deviceManagement/intents` was never paginated (silently lost
  findings in large tenants); every list now follows `@odata.nextLink`.
- **B6** GPO review regex-matched the entire report XML (noise on virtually
  every GPO); replaced with structured parsing of account-policy, firewall
  profile, AppLocker and configured admin-template nodes.
- **B7** Tenants relying on security defaults showed a false MFA fail; per-user
  registration data now surfaced.
- **B8** Admin-naming heuristic substring-matched surnames (Adams, Ahmadi,
  Privett); tokens are now anchored.
- **B9** Password verdict claimed a custom banned list is "REQUIRED" for CE;
  reworded to the actual requirement routes (MFA / 12+ chars / 8+ with deny
  list / throttling), including the on-prem domain password policy in hybrid.
- **B10** Mobile inventory ignored the check-in window (stale phones inflated
  scope).
- **B11** Settings-catalog detection regexed raw JSON; now parses per-setting
  definition ids/values (per-profile firewall states).
- **B12** AD group expansion failed on >5,000-member groups and foreign SIDs;
  replaced with an LDAP_MATCHING_RULE_IN_CHAIN query with cmdlet fallback.
- **B13** Hybrid CIM inventory used unbounded DCOM timeouts; now CIM sessions
  with a 15s operation timeout, and `-SkipHardwareInventory` to skip
  enrichment entirely.
- **B14** Directory-object resolution and per-user lookups are cached per run;
  shared Intune inventories (device configs, catalog policies + settings,
  intents, compliance policies) are fetched once instead of up to four times.
- **B15** The tool no longer disconnects a pre-existing Graph session it did
  not create.
- **B16** Every Graph URI lives in one central table.
- **B17** Launcher now forwards every parameter (incl. `-ADCredential`,
  `-ForceOverwrite`), and its output-folder default matches the engine
  (Documents).
- **B18** `-CheckInWindowWeeks` is validated (1-52); stale-account threshold
  validated (7-365).

### Changed
- `Get-IntuneEndpointReport.ps1` is now a deprecated compatibility wrapper
  that forwards to the module (`-DiagnoseBaselines` is accepted but ignored).
- Default report filename is `CyberEssentialsAudit_<timestamp>.xlsx`.

### Removed
- `Get-IntuneEndpointReport.cleaned.ps1` (stale duplicate).

## [1.x] - 2026

Initial prototype: single-script audit (`Get-IntuneEndpointReport.ps1`) with
TUI launcher, covering device inventory, MFA, firewall, mobile/MAM,
AutoPlay/AutoRun, shared accounts, application whitelisting, password
protection and privileged users.
