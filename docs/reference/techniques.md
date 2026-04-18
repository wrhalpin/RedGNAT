# Technique library reference

RedGNAT's technique library covers three ATT&CK tactic areas. All Phase 1 techniques are emulation-only: they observe, enumerate, and probe, but do not deliver payloads or modify state.

Every technique enforces the [safe-harbor scope](../explanation/safe-harbor.md) before any network activity, and all return `DRY_RUN` status when `scope.dry_run = true`.

---

## Discovery and Reconnaissance

### T1046 — Network Service Discovery

**Module:** `redgnat/techniques/discovery/network_scan.py`  
**Class:** `NetworkScanTechnique`  
**Tactic:** `discovery`

Uses `python-nmap` to perform port and service discovery against in-scope CIDR ranges. Validates every target CIDR against `scope.target_ranges` before scanning.

**Scope requirements:**
- `target_ranges` — CIDR blocks to scan
- `max_rate_per_minute` — applied as nmap rate limit

**Findings schema:**
```json
{
  "host": "10.0.0.5",
  "open_ports": [{"port": 22, "service": "ssh", "state": "open"}]
}
```

**GNAT intel ask when undetected:** Enrich exposed hosts via Shodan/Censys connectors. Check for CVEs on detected services via CISA KEV / VulnCheck.

---

### T1595.001 — Active Scanning: Scanning IP Blocks

**Module:** `redgnat/techniques/discovery/network_scan.py`  
**Class:** `NetworkScanTechnique`  
**Tactic:** `reconnaissance`

Registered as an alias of `NetworkScanTechnique`. Same implementation, different ATT&CK sub-technique categorisation.

---

### T1087.002 — Account Discovery: Domain Account

**Module:** `redgnat/techniques/discovery/ad_enum.py`  
**Class:** `ADEnumTechnique`  
**Tactic:** `discovery`

Enumerates Active Directory user accounts via LDAP (ldap3, read-only bind). Retrieves `sAMAccountName`, `userPrincipalName`, `memberOf`, `adminCount`, `userAccountControl`.

**Config required:** `[ldap]` section.

**Findings schema:**
```json
{
  "users_found": 412,
  "privileged_accounts": ["admin@example.com"],
  "gpos_found": 15
}
```

---

### T1069.002 — Permission Groups Discovery: Domain Groups

**Module:** `redgnat/techniques/discovery/ad_enum.py`  
**Class:** `ADEnumTechnique`  
**Tactic:** `discovery`

Enumerates AD security groups and their members via LDAP. Focuses on privileged groups: Domain Admins, Enterprise Admins, Schema Admins, Backup Operators.

---

### T1482 — Domain Trust Discovery

**Module:** `redgnat/techniques/discovery/ad_enum.py`  
**Class:** `ADEnumTechnique`  
**Tactic:** `discovery`

Queries `trustedDomain` objects via LDAP to map forest and external trusts.

---

### T1046 — Network Service Discovery (banner grabbing variant)

**Module:** `redgnat/techniques/discovery/service_enum.py`  
**Class:** `ServiceEnumTechnique`  
**Tactic:** `discovery`

TCP banner grabbing and service fingerprinting (SSH, HTTP, SMTP, FTP, SMB, RDP). Uses raw sockets with TLS wrapping where applicable. Lighter-weight than nmap — no privilege required.

---

### T1087.004 — Account Discovery: Cloud Account

**Module:** `redgnat/techniques/discovery/cloud_enum.py`  
**Class:** `CloudEnumTechnique`  
**Tactic:** `discovery`

Enumerates user accounts and service principals in Entra ID (Microsoft Graph API) and Okta (`/api/v1/users`).

**Config required:** `[entra]` and/or `[okta]`.

---

### T1069.003 — Permission Groups Discovery: Cloud Groups

**Module:** `redgnat/techniques/discovery/cloud_enum.py`  
**Class:** `CloudEnumTechnique`  
**Tactic:** `discovery`

Enumerates group membership in Entra ID (Microsoft Graph) and Okta groups.

---

### T1526 — Cloud Service Discovery

**Module:** `redgnat/techniques/discovery/cloud_enum.py`  
**Class:** `CloudEnumTechnique`  
**Tactic:** `discovery`

Enumerates cloud resources: Entra ID applications and service principals, AWS IAM identities, Okta applications.

---

## Initial Access — Phishing

### T1566.002 — Spearphishing Link

**Module:** `redgnat/techniques/phishing/spearphishing_link.py`  
**Class:** `SpearphishingLinkTechnique`  
**Tactic:** `initial-access`

Creates a link-based GoPhish campaign targeting in-scope domains. Polls GoPhish for click and credential submission statistics. `capture_passwords = False` by default — the landing page records click events only.

**Config required:** `[gophish]` section.

**Scope requirements:** `target_domains`

**Params (via `ctx.params`):**

| Param | Type | Description |
|-------|------|-------------|
| `campaign_name` | string | Override campaign name |
| `targets` | list of dicts | `[{"first_name": ..., "last_name": ..., "email": ..., "position": ...}]` |
| `duration_hours` | int | Campaign duration (default: `gophish.default_campaign_hours`) |

**Findings schema:**
```json
{
  "campaign_id": 42,
  "emails_sent": 25,
  "links_clicked": 8,
  "click_rate": 0.32,
  "credentials_submitted": 0
}
```

**GNAT intel ask when undetected:** Pull phishing campaign data from Cofense Intelligence / Proofpoint TAP. Verify email gateway sandbox coverage.

---

### T1566.001 — Spearphishing Attachment

**Module:** `redgnat/techniques/phishing/spearphishing_attachment.py`  
**Class:** `SpearphishingAttachmentTechnique`  
**Tactic:** `initial-access`

Sends an HTML email attachment containing a harmless beacon (tracking pixel + click link). No macros, no execution — purely a sandbox/gateway detection coverage test.

**Config required:** `[gophish]` section.

**GNAT intel ask when undetected:** Check attachment sandbox coverage in Proofpoint TAP / Mimecast.

---

### T1566 — Phishing (AiTM variant)

**Module:** `redgnat/techniques/phishing/mfa_phishing.py`  
**Class:** `MFAPhishingTechnique`  
**Tactic:** `initial-access`

Adversary-in-the-middle style credential and OTP harvest landing page served via GoPhish. `capture_passwords = False` by default — the page demonstrates the capability without storing credentials. Measures whether phishing-resistant MFA (FIDO2, passkeys) is enrolled.

---

## Credential Access and Identity

### T1110.003 — Brute Force: Password Spraying

**Module:** `redgnat/techniques/identity/password_spray.py`  
**Class:** `PasswordSprayTechnique`  
**Tactic:** `credential-access`

Controlled password spray against Entra ID, Okta, and/or Active Directory. **Only targets accounts explicitly listed in `scope.target_accounts`**. Shuffles account order each round, detects lockout and stops immediately. Adds random jitter between attempts.

**Config required:** `[entra]` and/or `[okta]` and/or `[ldap]`. `[scope] target_accounts`.

**Safety controls:**
- Stops entire spray on first lockout detection
- Per-account inter-attempt delay with jitter
- Never targets accounts not in `scope.target_accounts`

**GNAT intel ask when undetected:** Pull Okta smart lockout policy via Okta connector. Check Entra ID sign-in risk policy in Sentinel. Verify password spray detection rule in Silverfort.

---

### T1110.004 — Brute Force: Credential Stuffing

**Module:** `redgnat/techniques/identity/credential_stuffing.py`  
**Class:** `CredentialStuffingTechnique`  
**Tactic:** `credential-access`

Replays a list of known-breached credential pairs against IdPs. Filters `credential_pairs` to only those whose email matches a `scope.target_accounts` entry.

**GNAT intel ask when undetected:** Check if Entra ID 'Leaked Credentials' risk policy is active. Verify HIBP breach detection via HaveIBeenPwned connector.

---

### T1621 — Multi-Factor Authentication Request Generation

**Module:** `redgnat/techniques/identity/mfa_fatigue.py`  
**Class:** `MFAFatigueTechnique`  
**Tactic:** `credential-access`

Simulates MFA push-bombing (fatigue attack) against enrolled test users. Requires `confirm_mfa_fatigue_test = true` in `ctx.params` as an explicit safety gate. Capped at 10 pushes per account (`_MAX_PUSHES_CAP`).

**Params (required):**

| Param | Type | Description |
|-------|------|-------------|
| `confirm_mfa_fatigue_test` | bool | Must be `true` to proceed |
| `max_pushes` | int | Max pushes per account (capped at 10) |

**GNAT intel ask when undetected:** Verify FIDO2/phishing-resistant MFA enrollment rate via Entra ID / Okta connectors. Check MFA fatigue detection in Silverfort / Entra ID Protection.

---

### T1528 — Steal Application Access Token

**Module:** `redgnat/techniques/identity/oauth_abuse.py`  
**Class:** `OAuthAbuseTechnique`  
**Tactic:** `credential-access`

OAuth consent phishing via GoPhish — presents a fake OAuth consent page to in-scope users. `capture_passwords = False`. Measures whether anomaly detection fires on new OAuth consent grants.

**GNAT intel ask when undetected:** Audit OAuth app consent permissions via Entra ID connector. Check for MCAS/Defender Cloud Apps anomaly detection on new consents.

---

### T1539 — Steal Web Session Cookie

**Module:** `redgnat/techniques/identity/token_theft.py`  
**Class:** `TokenTheftTechnique`  
**Tactic:** `credential-access`

Read-only audit log analysis — not active exploitation. Measures session token lifetime policies, Continuous Access Evaluation (CAE) coverage in Entra ID, and impossible travel detection in Okta system logs.

**GNAT intel ask when undetected:** Review session token lifetime policies in Entra ID / Okta. Check CAE (Continuous Access Evaluation) coverage in Entra ID connector.

---

## Result status values

| Status | Meaning |
|--------|---------|
| `success` | Technique completed without triggering a detection alert — a **gap** |
| `partial` | Technique ran but produced incomplete results (some targets out of scope, some errors) |
| `blocked` | Scope check failed — target not in scope, run skipped cleanly |
| `detected` | Technique triggered a detection or alert (the defender caught it) |
| `error` | Unhandled exception during execution |
| `dry_run` | `scope.dry_run = true` — no network activity occurred |
