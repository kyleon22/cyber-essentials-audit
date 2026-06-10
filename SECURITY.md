# Security

## Read-only guarantee

The audit issues **only** HTTP GET requests to Microsoft Graph and read-only
Active Directory / Group Policy cmdlets (`Get-AD*`, `Get-GPO`, `Get-GPOReport`,
`Get-CimInstance`). It never writes to the tenant or the directory. A unit
test (`Module.Tests.ps1`) fails the build if any `Invoke-MgGraphRequest` call
with a mutating verb is introduced.

The only local writes are: the report workbook/JSON, the transcript log, and
(if you accept the prompt) installing the pinned PowerShell modules.

## Data sensitivity of the output

The workbook and JSON contain device names, user principal names, licence
assignments, privileged-group membership and policy configuration — exactly
the data an attacker would want for reconnaissance. Treat the output as
**confidential**:

* Default output location is the operator's private Documents folder, not the
  working directory.
* The exporter warns when the destination is a UNC path or mapped network
  drive.
* Generated reports are gitignored (`CyberEssentialsAudit_*.xlsx/json`).
* Cell values that begin with `=`, `+`, `-`, `@`, tab or CR are neutralised
  against CSV/formula injection before being written.

## Dependency policy

PSGallery modules are **version-pinned** (`Microsoft.Graph.Authentication
2.25.0`, `ImportExcel 7.8.10`) in both the module manifest and the launcher
preflight. The preflight never installs "latest", and it restores the
PSGallery `InstallationPolicy` to its prior state after installing. Update the
pins deliberately, test, and record the change in CHANGELOG.md.

## Authentication

* **Delegated**: interactive sign-in requesting read-only scopes; the module
  reuses an existing Graph session only when it already carries every needed
  scope, and only disconnects sessions it created itself.
* **App-only**: certificate-based (`-AuthMode App`); no client secrets are
  accepted. Grant the app registration only the application-permission
  equivalents of the documented read scopes.

## Output-file safety

* The output path must end in `.xlsx`.
* An existing file is only overwritten when it matches the report naming
  pattern or `-ForceOverwrite` is passed — a mistyped path cannot destroy an
  unrelated file.

## Code signing

Release artefacts should be Authenticode-signed before distribution to hosts
with `AllSigned` execution policies (the tool is expected to run on domain
controllers). Signing requires an organisation certificate and is performed in
the release pipeline; verify signatures on anything you did not build
yourself.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository (Security →
Advisories → Report a vulnerability). Please do not open public issues for
suspected vulnerabilities.
