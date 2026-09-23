# ShareScout Lite

A free, open-source PowerShell audit that shows who can reach what in SharePoint and OneDrive before Microsoft 365 Copilot shows it to them.

**Read-only, and nothing leaves your tenant.** The script calls Microsoft Graph and your own SharePoint Online with read-only queries and writes CSV files to your machine. It has no server, no telemetry and no upload.

## What Lite does

One run prints a tenant summary to the console:

- how many sites are open to every employee (Everyone / Everyone except external users in the site's permissions), out of all non-OneDrive sites
- how many Anyone links exist, and how many never expire
- how many guest accounts have access to at least one site

It also writes two CSVs:

| File | Contents |
|---|---|
| `anyone-links.csv` | Every anonymous (Anyone) sharing link: site, path, view/edit, file or folder, expiry (`never` if none) |
| `eeeu-sites.csv` | Every site where Everyone / Everyone except external users holds a permission, how it got there, item count, sensitivity label |

## What Lite does not do

The HTML oversharing report, per-site Copilot exposure scores, guest staleness, broken-inheritance, ownership and sensitivity-label checks, and white-label reports are in **ShareScout Solo and Pro** at **[sharescout.dev](https://sharescout.dev)**. That code is not in this repository: this script is the Lite build, not a paid build with a switch turned off.

## Requirements

- PowerShell 7+ (Windows, macOS or Linux)
- The Microsoft Graph PowerShell SDK and PnP.PowerShell:
  ```powershell
  Install-Module Microsoft.Graph -Scope CurrentUser
  Install-Module PnP.PowerShell -Scope CurrentUser
  ```
- A SharePoint Administrator (or Global Administrator) account. The script only reads, but listing every site and its permissions needs admin rights.

## One-time setup: register the PnP app

Since 2024 PnP.PowerShell no longer ships a shared app ID, so every tenant registers its own. Run this once as an admin:

```powershell
Register-PnPEntraIDAppForInteractiveLogin -ApplicationName "ShareScout" -Tenant contoso.onmicrosoft.com `
    -GraphDelegatePermissions "User.Read" -SharePointDelegatePermissions "AllSites.FullControl"
```

- It prints an **application (client) ID**. Pass it to the script as `-PnPClientId`.
- The permissions are *delegated*: the app can only do what the signed-in admin can already do, and ShareScout only reads. The tenant-admin cmdlets (`Get-PnPTenant`, `Get-PnPTenantSite`) need `AllSites.FullControl`. With `AllSites.Read` they fail with "Attempted to perform an unauthorized operation".
- You can inspect or delete the registration at any time under Entra ID → App registrations → ShareScout.

## Run it

Try it on demo data first. No tenant is needed:

```powershell
.\ShareScout-Audit.ps1 -MockDataPath .\test\mock-tenant.json
```

The demo data carries an `asOf` date that the script uses as "today" in mock mode, so the demo gives the same result on any day; real runs use the clock.

Then run it against your tenant:

```powershell
# full run: walks every library for Anyone links
.\ShareScout-Audit.ps1 -PnPClientId <app-id>

# quick first look: skips the item walk (no Anyone links), minutes on large tenants
.\ShareScout-Audit.ps1 -PnPClientId <app-id> -SkipItemScan

# a few sites only
.\ShareScout-Audit.ps1 -PnPClientId <app-id> -Sites https://contoso.sharepoint.com/sites/Finance, https://contoso.sharepoint.com/sites/HR
```

You sign in twice (Graph, then SharePoint) and consent to read-only Graph scopes. Add `-DeviceLogin` to sign in with a device code instead of a browser window (VS Code terminals, SSH, remote sessions). Other options: `-MaxItemsPerSite` (default 50000) and `-OutputPath`.

The CSVs contain file paths and site names. Treat them as confidential.

## License

The Lite script in this repository is released under the [MIT License](LICENSE). The ShareScout Solo and Pro editions are separate commercial products and are not covered by this license.

ShareScout is an independent tool and is not affiliated with, endorsed by, or sponsored by Microsoft.
