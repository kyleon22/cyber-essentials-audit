# Code Review & Enterprise Roadmap

**Scope:** `Get-IntuneEndpointReport.ps1` (2,326 lines) + `Start-CyberEssentialsAudit.ps1` (304 lines)
**Reviewed:** 10 June 2026
**CE baseline:** Danzell question set (v3.3), in force for all assessments started after 27 April 2026

---

## 1. Overall verdict

This is a strong, well-engineered prototype — far beyond proof-of-concept. The supply-chain hygiene (pinned modules, PSGallery trust restore), output safety (overwrite guard, UNC warning), read-only design, and hybrid de-duplication logic are genuinely above average for tooling at this stage.

It is **not yet enterprise-ready**, for three reasons, in order of importance:

1. **Accuracy bugs** — several checks can report wrong results today (Section 2). This conflicts directly with your "100% accurate" goal.
2. **CE coverage gaps** — two of the five CE technical controls (malware protection, security update management) are not audited at all, and both now carry **auto-fail** rules under Danzell (Section 3).
3. **Architecture** — a 2,300-line monolith with no tests, no logging, no machine-readable output, delegated-auth only, and no summary verdict tab (Section 4).

---

## 2. Accuracy bugs (fix before anything else)

### Critical — wrong results

| # | Issue | Where | Detail / fix |
|---|-------|-------|--------------|
| B1 | **Formula-injection neutraliser never fires for `=` `+` `-` `@`** | `Protect-CellText`, ~line 1896 | `'=+-@' -contains $Value[0]` treats the LHS string as a one-element collection, so it compares `"=+-@" -eq "="` → always false. Only the tab/CR branch works. Fix: `[char[]]'=+-@' -contains $Value[0]` or `'=+-@'.IndexOf($Value[0]) -ge 0`. The README claims this safeguard works — it currently doesn't. |
| B2 | **MFA headline counts disabled and report-only CA policies** | ~lines 701–709 | A policy with `state = 'disabled'` or `'enabledForReportingButNotEnforced'` is counted in "Policies enforcing MFA: N". Under Danzell, MFA on cloud services is an **auto-fail** item — overstating coverage here is the worst possible inaccuracy. Count only `enabled` policies in the headline; show others separately. |
| B3 | **Servers in Intune are misclassified as Windows 10/11 workstations** | `Get-WindowsFriendlyOS` ~line 82, `IsServer` ~line 489 | Cloud devices get `IsServer` from a regex on the friendly OS name, which is derived from the build map. Server 2022 (build 20348) isn't in the map → falls to "Windows 10 (build 20348)" → classified as a workstation with the wrong OS name. Server 2019 (17763) maps to "Windows 10 1809". Use `skuFamily`/`operatingSystemEdition` or add server builds (14393/16299/17763/20348/26100-server) to the logic. |
| B4 | **No unsupported/EOL OS detection** | Device list | Windows 10 22H2 went end-of-support in October 2025. Unsupported OS = CE fail, yet the report lists Win10 devices with no flag. Add an EOL date table per build (and macOS major versions — Apple effectively supports current and two prior) and a red Supported/EOL column. Also: build map is missing Windows 11 25H2 (26200). |
| B5 | **Intents endpoint is never paginated** | ~lines 798, 1086, 1119, 1260 | Every other list follows `@odata.nextLink`; the four `deviceManagement/intents` queries don't. Tenants with many endpoint-security profiles/baselines will silently lose findings in firewall, AutoPlay and app-control tabs. |
| B6 | **GPO control matching is regex-over-entire-XML** | ~lines 1397–1440 | `(?i)password` matches virtually every GPO report XML (schema text, defaults), so the Password/lockout findings are mostly noise; `firewall` is similar. Parse the actual setting nodes (`SecurityOptions`, `Account` policy, `WindowsFirewallSettings`, AppLocker `RuleCollection`) instead of substring-matching the document. |

### High — misleading results

| # | Issue | Where | Detail / fix |
|---|-------|-------|--------------|
| B7 | **MFA tab ignores security defaults and per-user MFA** | MFA section | A tenant relying on security defaults (which enforce MFA) shows "No CA policy enforcing MFA" — a false fail. The script already reads security defaults for the Password tab; surface it on the MFA tab too, plus per-user MFA state and `reports/authenticationMethods/userRegistrationDetails` for actual registration coverage. |
| B8 | **Admin-naming regex misfires on ordinary surnames** | `Get-PrivClass` ~line 1520 | `(?i)(adm|admin|priv|svc|...)` substring-matches "Adams", "Ahmadi", "Privett" → classified as admin-named → the key "standard user with admin" finding is suppressed (false negative). Anchor the tokens (`^adm[._-]|[._-]adm$|\badmin\b` etc.). |
| B9 | **Password verdict overstates the CE requirement** | ~lines 1365–1372 | The text says a custom banned list is "REQUIRED to fulfil the Cyber Essentials requirement". CE (Willow and Danzell) accepts several routes: 12+ char minimum with no maximum, deny lists, throttling/lockout. Danzell raises the minimum length expectation to 12. Custom banned lists also require Entra ID P1/P2. Reword the verdict to assess the actual requirement, noting Microsoft's global banned list + smart lockout as partial evidence. |
| B10 | **Mobile inventory ignores the check-in window** | ~lines 870–872 | Windows/macOS are filtered to the last N weeks; Android/iOS are not — stale mobiles inflate the asset list (scope accuracy matters more under Danzell). Apply the same `lastSyncDateTime` filter. |
| B11 | **Settings-catalog detection is regex over raw JSON** | firewall ~779, app-control ~1239 | Matching `enablefirewall_true` in the JSON blob can't distinguish which profile (domain/private/public) is set, and anything else becomes "Configured (review policy)". Resolve `settingDefinitionId` → definition display name via `deviceManagement/configurationSettings` (cacheable) and report per-setting values. Same approach fixes app-control. |

### Medium — robustness/operational

- **B12** `Get-ADGroupMember -Recursive` fails on groups >5,000 members and on foreign security principals; orphaned SIDs throw. Prefer an LDAP `LDAP_MATCHING_RULE_IN_CHAIN` query (`memberOf:1.2.840.113556.1.4.1941:=<groupDN>`) with fallback.
- **B13** Hybrid CIM inventory is serial, one device at a time, with default DCOM timeouts — on a 500-device estate this can run for hours. Use `CimSession` over WinRM with a short `-OperationTimeoutSec`, fan out with runspaces/`ForEach-Object -Parallel` (PS7), and make hardware enrichment opt-in (`-SkipHardwareInventory`).
- **B14** `Resolve-DirObject` has no cache — the same excluded group in 10 CA policies = 10 Graph calls. Add a hashtable cache like `$privUserCache`.
- **B15** `Disconnect-MgGraph` in `finally` tears down any pre-existing Graph session the operator had. Only disconnect if the script created the connection.
- **B16** Heavy reliance on the **beta** Graph endpoint. Unavoidable for Intune config today, but isolate every URI in one place (constant table) so endpoint churn is a one-line fix, and use v1.0 where it now suffices.
- **B17** Launcher drift: says output defaults to "current folder" (engine uses Documents); `Open-OutputFolder` defaults to cwd; launcher doesn't forward `-ADCredential`, `-ForceOverwrite`, or the module-version pins.
- **B18** No validation on `-CheckInWindowWeeks` (0/negative accepted). Add `[ValidateRange(1,52)]`.

---

## 3. Cyber Essentials coverage gaps (Danzell v3.3)

The five CE controls vs current tab coverage:

| CE control | Covered today | Gap |
|---|---|---|
| Firewalls | Software firewall (Intune + GPO) | macOS firewall not checked; boundary firewall is inherently manual — add a documented manual-evidence row rather than silence |
| Secure configuration | AutoPlay/AutoRun, shared accounts (heuristic) | Default-password change and device-locking (PIN/lock compliance settings) not surfaced |
| User access control | MFA, privileged users, shared accounts | Per-user MFA coverage (B7); leaver/stale accounts (last sign-in >N days); guest account review |
| **Malware protection** | **Nothing** | Add a Defender AV tab: AV policies (endpoint security + baselines), real-time protection, signature update cadence, PUA protection, macOS AV. App allow-listing tab partially overlaps but Danzell treats malware protection distinctly |
| **Security update management** | **Nothing** | **Auto-fail territory under Danzell** (high/critical patches within 14 days). Add a tab covering: Update rings / WUfB policies and their deadline+grace settings (flag anything allowing >14 days), feature-update policies, Autopatch if present, driver update policy, and the unsupported-OS findings from B4. Third-party app patching = manual-evidence row |

Two Danzell-specific additions worth building now:

1. **Summary / verdict tab (first tab).** Your stated goal — "easy to see all the controls that are failing and why" — is currently unmet: the reader must interpret nine tabs. Add a tab with one row per CE sub-requirement: control, automated verdict (Pass / Fail / Manual check required), one-line reason, link to the detail tab. RAG-coloured. This is the single highest-value change in the whole roadmap.
2. **Scope worksheet.** Danzell requires a detailed scope description and per-legal-entity declarations, with scope text published. A tab capturing tenant ID, domains, device counts by type, exclusions + justification gives the assessor exactly what the new question set asks for.

Also distinguish **Pass / Fail / Unknown** consistently: "no policy found" can mean not configured *or* insufficient permissions. Capture which Graph calls failed and mark affected checks "Unknown — permission/API error", never an implicit pass or fail. This is essential for the accuracy claim.

---

## 4. Roadmap to enterprise-ready

### Phase 1 — Correctness (do first)

Fix B1–B11. Add Pester tests with captured Graph JSON fixtures for every detection function (the pure functions — `Get-WindowsFriendlyOS`, `Get-AssignmentSummary`, `Protect-CellText`, `Get-PrivClass`, autoplay walker — are easily testable today and B1/B3/B8 would all have been caught). Add PSScriptAnalyzer with a ruleset to CI. Add `Start-Transcript`-based run logging next to the report.

### Phase 2 — Restructure into a module

Convert the monolith to a module (`CyberEssentialsAudit`):

```
CyberEssentialsAudit/
  CyberEssentialsAudit.psd1        # manifest, version, RequiredModules
  Public/  Invoke-CeAudit.ps1, Export-CeReport.ps1
  Private/ Checks/   Get-CeMfaFindings.ps1, Get-CeFirewallFindings.ps1, ...
           Graph/    Invoke-CeGraphRequest.ps1 (paging, caching, URI table)
           Excel/    one writer per tab
  Tests/   *.Tests.ps1  + Fixtures/*.json
```

Key design rule: every check returns the same typed object — `{Control; CheckId; Status (Pass/Fail/Manual/Unknown); Evidence; Reason; DetailRows}` — and the Excel layer renders it. That decouples collection from presentation, makes the Summary tab trivial, and enables `-OutputFormat Json` for pipelines/SIEM ingestion alongside the workbook. Keep `Start-CyberEssentialsAudit.ps1` as a thin TUI over `Invoke-CeAudit`.

### Phase 3 — Auth & operations

- **App-only auth** (certificate-based) as an alternative to delegated, with `-AuthMode Delegated|App` — required for scheduled/unattended enterprise runs and for MSP scenarios. Document the least-privilege app registration (the same read scopes as application permissions).
- Verify throttling behaviour: the Graph PowerShell SDK retries 429s, but the per-user/per-policy fan-out (B14) should be reduced anyway via caching and `$batch` requests.
- Structured progress (`Write-Progress`), `-Verbose` stream, non-zero exit codes on failure, and a machine-readable run manifest (who ran, when, tenant, scopes granted, checks skipped) embedded as a hidden "Run info" tab — auditors will ask.

### Phase 4 — Distribution & trust

- Semantic versioning in the manifest + CHANGELOG.
- **Authenticode-sign** the module and launcher (enterprise hosts with AllSigned policies, and you're asking people to run this on domain controllers — signing is non-negotiable).
- CI (GitHub Actions): PSScriptAnalyzer → Pester → build → sign → release zip; optionally publish to a private PSResource repository.
- A SECURITY.md covering the read-only guarantee, data sensitivity of the output, and the pinned-dependency policy you already implement.

### Phase 5 — Differentiators (after the above)

- Multi-tenant support (GDAP/CSP) for MSP use — loop tenants, one workbook each plus a roll-up.
- Run-over-run diff ("what changed since the last audit") — powerful for the annual re-certification story.
- Optional CE+ evidence helpers (screenshot checklists, sample-device selection).

---

## 5. Suggested order of work

1. Summary/verdict tab + Pass/Fail/Manual/Unknown model (Section 3) — biggest user-visible win, forces the data-model refactor in the right direction.
2. Bug fixes B1–B6 (critical accuracy), then B7–B11.
3. Security update management + malware protection tabs (Danzell auto-fail exposure).
4. Module restructure + Pester/PSSA + CI.
5. App-only auth, signing, versioned releases.
6. Phase 5 differentiators.

---

*Line numbers refer to the files as of this review. CE references: IASME/NCSC Danzell question set (v3.3, effective 27 Apr 2026) — verify exact sub-requirement wording against the published question set before encoding verdict text.*
