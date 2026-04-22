---
layout: default
title: Configuration Reference
description: All INI configuration keys, sections, and discovery rules.
---

# Configuration reference

RedGNAT uses INI-format configuration (same convention as GNAT and SandGNAT). The config file is searched in this order:

1. Path in the `REDGNAT_CONFIG` environment variable
2. `~/.redgnat/config.ini`
3. `./redgnat.ini` in the current directory

Use the template at `config/config.ini.example` as a starting point.

---

## `[redgnat]` — Core settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `db_url` | string | `postgresql://redgnat:redgnat@localhost:5432/redgnat` | PostgreSQL connection URL (psycopg3 format) |
| `redis_url` | string | `redis://localhost:6379/0` | Redis URL used as Celery broker and result backend |
| `dry_run` | bool | `false` | Global dry-run flag. When `true`, every technique logs what it *would* do and returns `DRY_RUN` status — no network activity reaches any target |
| `log_level` | string | `INFO` | Python log level: `DEBUG`, `INFO`, `WARNING`, or `ERROR` |

---

## `[gnat]` — GNAT integration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `config_path` | path | `~/.gnat/config.ini` | Path to an existing GNAT config file. RedGNAT passes this to `GNATClient(config_path=...)` |
| `poll_interval_seconds` | int | `300` | How often Celery beat polls GNAT for new campaigns and TTPs |
| `min_confidence` | float | `0.6` | Minimum GNAT confidence score (0.0–1.0). Campaigns below this threshold are ignored during normalisation |

---

## `[sandgnat]` — SandGNAT sandbox integration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `base_url` | string | `http://localhost:5000` | SandGNAT export API base URL |
| `api_key` | string | *(empty)* | SandGNAT `INTAKE_API_KEY` |
| `poll_interval_seconds` | int | `120` | How often to poll SandGNAT for new analyses |
| `min_severity` | string | `medium` | Minimum analysis severity to ingest: `low`, `medium`, `high`, or `critical` |

---

## `[gophish]` — GoPhish phishing campaigns

Required for phishing techniques (T1566.001, T1566.002, T1566, T1528).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `base_url` | string | *(empty)* | GoPhish API base URL including port (e.g. `https://gophish.example.com:3333`) |
| `api_key` | string | *(empty)* | GoPhish API key |
| `sending_profile_id` | int | `1` | Default sending profile ID used for campaigns |
| `landing_page_base_url` | string | *(empty)* | Base URL where phishing landing pages are served. Must be reachable by targets |
| `default_campaign_hours` | int | `72` | Default campaign duration in hours |

---

## `[scope]` — Safe-harbor scope

**Every technique validates all targets against this scope before acting.** Misconfiguration here is the most common source of incidents.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `target_ranges` | CSV of CIDRs | *(empty)* | IP ranges permitted for network techniques. Comma-separated (e.g. `10.0.0.0/8,172.16.0.0/12`) |
| `excluded_ranges` | CSV of CIDRs | *(empty)* | IP ranges that are NEVER touched, regardless of `target_ranges`. Takes precedence |
| `target_domains` | CSV of strings | *(empty)* | DNS domains in scope for phishing and web techniques |
| `excluded_domains` | CSV of strings | *(empty)* | Domains explicitly excluded. Takes precedence over `target_domains` |
| `target_accounts` | CSV of UPNs | *(empty)* | Email addresses / UPNs of dedicated test accounts. **Only these accounts** are targeted by credential techniques (password spray, MFA fatigue, etc.) |
| `max_rate_per_minute` | int | `30` | Maximum requests per minute across all techniques, per target host |

---

## `[entra]` — Microsoft Entra ID / Azure AD

Required for cloud enumeration and identity techniques targeting Entra ID.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tenant_id` | string | *(empty)* | Azure AD tenant ID (UUID format) |
| `client_id` | string | *(empty)* | App registration client ID. The app needs appropriate read and test account permissions |
| `client_secret` | string | *(empty)* | App registration secret |
| `authority` | string | `https://login.microsoftonline.com` | OAuth2 authority base URL |

---

## `[okta]` — Okta identity provider

Required for identity techniques targeting Okta (T1110.003, T1621).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `base_url` | string | *(empty)* | Okta org URL (e.g. `https://example.okta.com`) |
| `api_token` | string | *(empty)* | Okta API token (SSWS or OAuth2 bearer) |

---

## `[ldap]` — Active Directory / LDAP

Required for AD enumeration techniques (T1087.002, T1069.002, T1482).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `server` | string | *(empty)* | Domain controller address (e.g. `ldap://dc.example.com` or `ldaps://dc.example.com`) |
| `bind_dn` | string | *(empty)* | Service account distinguished name for read-only LDAP enumeration |
| `bind_password` | string | *(empty)* | Service account password |
| `base_dn` | string | *(empty)* | LDAP search base (e.g. `DC=example,DC=com`) |
| `use_ssl` | bool | `false` | Use LDAPS (TLS on port 636) |
| `port` | int | `389` | LDAP port (use `636` with `use_ssl = true`) |

---

## `[aws]` — Amazon Web Services

Required for cloud enumeration against AWS (T1087.004, T1069.003, T1526).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `aws_access_key_id` | string | *(empty)* | AWS access key for a read-only IAM identity |
| `aws_secret_access_key` | string | *(empty)* | AWS secret access key |
| `aws_default_region` | string | `us-east-1` | Default AWS region |
| `assume_role_arn` | string | *(empty)* | If set, RedGNAT will assume this IAM role ARN before enumerating. Recommended for least-privilege deployments |

---

## `[feedback]` — Gap reporting and probe generation

Controls the bidirectional feedback loop. See [Bidirectional feedback loop](../explanation/automation/feedback-loop.md) for context.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable automatic gap reporting after each emulation run |
| `push_to_gnat` | bool | `true` | Push gap STIX Notes to GNAT via `GNATClient.upsert_object()` immediately after each run |
| `probe_generation_enabled` | bool | `true` | Enable AI-driven follow-on probe generation using GNAT's `LLMClient` |
| `probe_model` | string | `claude-3-5-sonnet-20241022` | LLM model identifier passed to `gnat.agents.LLMClient` |
| `max_probes_per_report` | int | `10` | Maximum `ProbeRequest` objects generated per gap report. Guards against runaway scheduling when many techniques go undetected |
