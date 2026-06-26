# Site Network Compliance

Read-only compliance auditing for Meraki MX firewalls and UniFi switches.

The auditor collects Meraki data first, then UniFi data. Meraki VLAN interface IPs are used as reference data for UniFi checks such as DHCP Guard trusted server IPs. The tool writes JSON, CSV, and summary reports, and includes an optional local web UI for browsing findings.

## Quick Start

Use the local wrapper script. It automatically runs with the project `.venv` and current `src/` code.

```bash
cp example.env .env
cp config/config.example.yaml config/config.yaml

.venv/bin/pip install -r requirements.txt
./audit.py
```

Reports are written to `reports/`:

- `compliance_report.json`: full report used by the web UI
- `compliance_findings.csv`: spreadsheet-friendly finding list
- `summary.json`: high-level counts and findings by site

## Secrets

Secrets belong in `.env`, not in YAML.

```bash
UNIFI_USERNAME=readonly-admin@example.com
UNIFI_PASSWORD=change-me
UNIFI_MFA_SECRET=
MERAKI_DASHBOARD_API_KEY=change-me
```

`UNIFI_MFA_SECRET` must be the base32 TOTP seed, not a one-time code.

UniFi API key support is experimental only. The current UniFi API key endpoints have not been reliable enough to treat as the primary authentication method. You can test a key per controller by adding an `api_key_env` entry in `config/config.yaml`, then defining that environment variable in `.env`. If the API key endpoint fails, the collector falls back to session login.

## Runtime Config

Runtime settings live in `config/config.yaml`.

Important fields:

- `audit.output_dir`: where reports are written
- `audit.workers.controllers`: parallel UniFi controller workers
- `audit.workers.sites_per_controller`: parallel UniFi site workers per controller
- `audit.workers.meraki_networks`: parallel Meraki network workers
- `audit.verify_tls`: TLS verification for UniFi controller requests
- `unifi.controllers`: controller names, URLs, credentials env names, and optional site filters
- `meraki.org_ids`: optional Meraki org ID allowlist
- `meraki.include_networks` / `exclude_networks`: optional Meraki network filters
- `exceptions.ignored_sites` / `ignored_devices`: skip known labs or intentionally nonstandard devices

Meraki rate limiting is org-scoped. The default leaves room under Meraki's documented 10 requests per second per organization limit:

```yaml
meraki:
  requests_per_second_per_org: 6
  rate_limit_wait_seconds: 60
  rate_limit_retries: 5
```

If Meraki returns `429`, the script honors `Retry-After` when available and otherwise sleeps for `rate_limit_wait_seconds`.

## Development Cache

During rule, report, or UI development, use the cache so repeated runs do not re-query Meraki and UniFi.

Refresh the cache from live APIs:

```bash
./audit.py --cache-mode refresh
```

Reuse cached collected data:

```bash
./audit.py --cache-mode read
```

The cache file defaults to:

```text
cache/target_cache.json
```

`cache/` is ignored by git. The cache may contain device names, site names, IP addresses, VLANs, and other collected configuration data, so treat it as internal data.

## Compliance Rules

Compliance rules live in `config/compliance.yaml`. YAML is used because it is easier for humans to maintain than JSON for this type of rule file. `schemas/compliance.schema.json` is included for editor validation.

Strict list checks are enabled by default. For example, if a VLAN section lists VLANs `2`, `10`, and `20`, then VLAN `50` is a finding unless it is explicitly ignored.

Example strict VLAN rule with ignored items:

```yaml
vlans:
  strict: true
  key: vlan
  ignore_items:
    - 1
  items:
    - vlan: 2
      name: Management
```

Use `ignore_items` for platform defaults or harmless built-ins, such as VLAN 1, that may appear but are not part of the compliance standard.

DHCP option checks are scoped to the requested option code. This rule requires DHCP option 15 to be `vs.local`, while safely ignoring other option codes such as 66:

```yaml
dhcpOptions:
  $dhcp_option:
    code: "15"
    value: "vs.local"
```

UniFi rules can reference Meraki VLAN interface IPs:

```yaml
dhcpguard_server:
  $meraki_vlan_interface_ip: 100
```

The auditor matches UniFi sites to Meraki sites by exact normalized site name first. If names differ, it uses the UniFi switch management IP and finds the single Meraki VLAN 2 subnet containing that IP.

## Exceptions

Use exceptions for known labs, test gear, or sites that should not affect compliance results.

Exact device ignore:

```yaml
exceptions:
  ignored_devices:
    - LAB-SWITCH-01
```

Regex with platform:

```yaml
exceptions:
  ignored_sites:
    - platform: unifi
      regex: ".*LAB.*"
```

Use compliance `ignore_items` for ignored configuration objects inside a section, such as VLAN 1. Use exceptions for whole sites or devices.

## Web UI

Run an audit first so `reports/compliance_report.json` exists.

Use either the local `uvicorn` option or the Docker Compose option. You do not need both.

Local Python option:

```bash
PYTHONPATH=src .venv/bin/uvicorn vet_compliance.web.app:app --host 0.0.0.0 --port 8000
```

Open:

```text
http://localhost:8000
```

Docker Compose option:

```bash
docker compose run --rm auditor
docker compose up -d web
```

Open:

```text
http://localhost:8080
```

The Docker web container serves plain HTTP on port `8080`. Use the optional reverse proxy configs if you want local HTTPS.

The UI includes:

- device and site compliance counts
- searchable finding table
- per-column filters in the table header
- sorting
- pagination
- human-readable expected and found values

## Docker

Build and run the auditor:

```bash
docker compose run --rm auditor
```

Start the web UI:

```bash
docker compose up -d web
```

If Docker Hub is unavailable, override the Python base image:

```bash
PYTHON_IMAGE=registry.example.com/library/python:3.13-slim docker compose build
```

## Optional Reverse Proxy

Example nginx and Apache configs are in `deploy/`.

To install a local self-signed certificate and proxy config:

```bash
scripts/install_web_proxy.sh nginx
scripts/install_web_proxy.sh apache
```

Review hostnames, paths, and local service ports before using this outside a lab.

## Common Commands

Run a normal live audit:

```bash
./audit.py
```

Increase logging:

```bash
./audit.py --log-level DEBUG
```

Use alternate config or rules:

```bash
./audit.py --config config/config.yaml --rules config/compliance.yaml
```

## Troubleshooting

YAML does not allow tabs. If you see:

```text
found character '\t' that cannot start any token
```

replace tabs with spaces in the YAML file named in the traceback.

If many UniFi findings say missing Meraki reference data, site matching likely failed. The matching logic needs either similar site names or a UniFi management IP that belongs to exactly one Meraki VLAN 2 subnet.

If the web UI shows stale data, rerun:

```bash
./audit.py
```

or, during development:

```bash
./audit.py --cache-mode read
```

If Meraki collection is slow, check:

```yaml
audit:
  workers:
    meraki_networks: 8
meraki:
  requests_per_second_per_org: 6
```

If Meraki throttles, lower `requests_per_second_per_org`.

## Read-only Design

The collectors only read data.

- Meraki uses Dashboard API read endpoints for organizations, networks, devices, appliance VLANs, firewall settings, and site-to-site VPN settings.
- UniFi uses controller GET endpoints for sites, devices, networks, WLANs, port profiles, RADIUS profiles, AP groups, and settings.

The script is intended for audit/reporting only and should not write configuration to Meraki or UniFi.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
