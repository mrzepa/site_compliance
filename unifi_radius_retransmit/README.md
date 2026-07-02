# UniFi RADIUS Retransmit Remediation

Standalone daily job that:

1. Logs into one or more UniFi controllers.
2. Resolves CSV site names to UniFi site IDs.
3. Pulls all switches in each matched site.
4. Uses Ansible SSH fan-out to run:

```text
radius default-config retransmit 10 timeout 30
```

The service is intentionally independent of the repo's compliance auditor code. It copies the small amount of UniFi controller client behavior it needs.

## Index

- [Requirements](#requirements)
- [Files](#files)
- [Setup](#setup)
- [Run](#run)
- [Grafana Login](#grafana-login)
- [Production Access](#production-access)
- [Configuration Reference](#configuration-reference)
- [Metrics](#metrics)
- [Grafana Dashboard](#grafana-dashboard)
- [Parallelism](#parallelism)
- [Notes](#notes)

## Requirements

Core requirements:

- Docker Engine or Docker Desktop with Docker Compose v2.
- Network access from the container host to the UniFi controller.
- Network access from the container host to every target switch on SSH port `22`.
- A UniFi controller account that can list sites and devices.
- Switch SSH enabled, with username `admin`.
- One switch SSH password per UniFi site.
- The UniFi site names in `secrets/sites.csv` must match the UniFi controller site display names.
- UniFi controller credentials are stored in `secrets/secrets.vault.yaml`.

Linux/macOS requirements:

- Docker Engine or Docker Desktop.

Windows requirements:

- Docker Desktop.
- PowerShell.

Ansible and `ansible-vault` requirements:

- All Ansible and `ansible-vault` commands run inside the `radius` container.
- Build the container before encrypting `secrets/sites.csv`.

Monitoring and production access requirements:

- Grafana and Prometheus are included in `docker-compose.yml`.
- A production deployment should have a valid SSL/TLS certificate.
- Use Apache, Nginx, or IIS as a reverse proxy in front of Grafana for HTTPS access.
- Keep Prometheus `9090` and raw metrics `9108` internal-only unless there is a specific monitoring requirement to expose them.

## Files

- `config/config.yaml`: local runtime configuration, copied from `config/config.example.yaml`
- `config/secrets.example.yaml`: example UniFi controller secret template
- `config/sites.example.csv`: example site/password CSV template
- `secrets/secrets.vault.yaml`: ansible-vault encrypted UniFi controller credentials
- `secrets/sites.vault.csv`: ansible-vault encrypted site/password CSV
- `secrets/.vault_pass`: local ansible-vault password file
- `ansible.cfg`: Ansible defaults
- `app/inventory.py`: dynamic Ansible inventory builder
- `playbooks/radius_default_config.yml`: switch SSH playbook
- `app/scheduler.py`: daily scheduler plus Prometheus metrics endpoint

## Setup

Run commands from the `unifi_radius_retransmit` folder.

Create the local working files.

Linux/macOS:

```bash
mkdir -p secrets
cp config/sites.example.csv secrets/sites.csv
cp config/secrets.example.yaml secrets/secrets.yaml
cp config/config.example.yaml config/config.yaml
```

Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force secrets
Copy-Item config/sites.example.csv secrets/sites.csv
Copy-Item config/secrets.example.yaml secrets/secrets.yaml
Copy-Item config/config.example.yaml config/config.yaml
```

Edit `config/config.yaml` with each UniFi controller name and URL. The controller `name` must match the key in `secrets/secrets.yaml`:

```yaml
unifi:
  controllers:
    - name: controller-a
      base_url: https://192.0.2.10:8443
```

Edit `secrets/secrets.yaml` with the UniFi controller credentials:

```yaml
unifi:
  controllers:
    controller-a:
      username: readonly-admin@example.com
      password: change-me
      mfa_secret:
      api_key:
```

Edit `secrets/sites.csv`. Use the UniFi controller site display name in `site_name`. The password is the shared SSH password for all switches at that site.

Create the vault password file before encrypting any secret files. Ansible cannot create `secrets/secrets.vault.yaml` or `secrets/sites.vault.csv` until `secrets/.vault_pass` exists:

Linux/macOS:

```bash
echo "replace-with-a-real-vault-password" > secrets/.vault_pass
chmod 600 secrets/.vault_pass
```

Windows PowerShell:

```powershell
Set-Content -Path secrets/.vault_pass -Value "replace-with-a-real-vault-password" -NoNewline
```

Build the container image so `ansible-vault` is available:

```bash
docker compose build radius
```

Encrypt the UniFi controller secrets from inside the container.

Linux/macOS:

```bash
docker compose run --rm radius ansible-vault encrypt secrets/secrets.yaml
mv secrets/secrets.yaml secrets/secrets.vault.yaml
```

Windows PowerShell:

```powershell
docker compose run --rm radius ansible-vault encrypt secrets/secrets.yaml
Rename-Item secrets/secrets.yaml secrets.vault.yaml
```

Encrypt the site/password CSV from inside the container.

Linux/macOS:

```bash
docker compose run --rm radius ansible-vault encrypt secrets/sites.csv
mv secrets/sites.csv secrets/sites.vault.csv
```

Windows PowerShell:

```powershell
docker compose run --rm radius ansible-vault encrypt secrets/sites.csv
Rename-Item secrets/sites.csv sites.vault.csv
```

Ansible reads `secrets/.vault_pass` through `ansible.cfg`.

Before running, confirm these files exist:

- `config/config.yaml`
- `secrets/.vault_pass`
- `secrets/secrets.vault.yaml`
- `secrets/sites.vault.csv`

## Run

Linux/macOS:

```bash
docker compose up -d --build
```

Windows PowerShell:

```powershell
docker compose up -d --build
```

The remediation job runs on container start by default and then daily at `scheduler.daily_at`.

Prometheus is available at `http://localhost:9090`.
Grafana is available at `http://localhost:3000`.
The job metrics endpoint is exposed at `http://localhost:9108/metrics`.

## Grafana Login

Open Grafana at `http://localhost:3000`.

Default credentials for the Grafana container are:

```text
Username: admin
Password: admin
```

Grafana will prompt you to change the password after the first login. Change it immediately and store the new password in your password manager.

The provisioned dashboard is under:

```text
Dashboards > Radius > Radius Remediation
```

## Production Access

The Compose file publishes Grafana, Prometheus, and the metrics endpoint directly for simple local access:

- Grafana: `3000`
- Prometheus: `9090`
- Radius metrics: `9108`

For production, do not expose these ports directly to the internet. Put Grafana behind a reverse proxy with a valid SSL/TLS certificate, such as Apache, Nginx, or IIS. Prometheus and the raw metrics endpoint should usually be reachable only from the monitoring host or internal network.

Recommended production pattern:

- Public HTTPS URL terminates TLS at Apache, Nginx, or IIS.
- Reverse proxy forwards only Grafana traffic to `http://127.0.0.1:3000`.
- Firewall restricts `9090` and `9108` to localhost or the monitoring subnet.
- Grafana admin password is changed from the default.
- If possible, add SSO, VPN-only access, or upstream authentication at the reverse proxy.

Example reverse proxy templates are included:

- Nginx: `deploy/nginx/radius-grafana.conf`
- Apache: `deploy/apache/radius-grafana.conf`
- IIS: `deploy/iis/setup-radius-grafana-proxy.ps1`

These are starting templates. Replace `radius.example.com`, certificate paths, and IIS certificate thumbprints before production use.

## Configuration Reference

```bash
cp config/config.example.yaml config/config.yaml
cp config/secrets.example.yaml secrets/secrets.yaml
```

Edit:

- `config/config.yaml` for controller URLs, parallelism, schedule, and SSH settings
- `secrets/secrets.vault.yaml` for UniFi controller credentials
- `secrets/sites.vault.csv` for site-specific switch passwords

## Metrics

- `radius_last_run_success`
- `radius_last_run_timestamp`
- `radius_last_run_duration_seconds`
- `radius_switches_total`
- `radius_switches_failed`
- `radius_sites_missing`: count of rows in `secrets/sites.vault.csv` whose `site_name` did not match any UniFi controller site during the last inventory lookup
- `radius_site_switches_total{site="..."}`
- `radius_site_switches_success{site="..."}`
- `radius_site_switches_failed{site="..."}`
- `radius_switch_status{site="...",switch="...",host="..."}`

## Grafana Dashboard

Grafana is provisioned automatically with:

- A Prometheus datasource pointing at `http://prometheus:9090`
- A `Radius Remediation` dashboard in the `Radius` folder
- A `Site Mode` dropdown with `All sites` and `Failed sites`
- A `Site` dropdown that can show all sites or only sites where `radius_site_switches_failed > 0`

The dashboard includes sites with failures, total targeted switches, failed switches, success rate, failures by site, per-switch status, run duration, and a count of CSV sites not found in UniFi.

Suggested alert expressions for later Alertmanager routing:

```yaml
groups:
  - name: radius
    rules:
      - alert: UnifiRadiusRetransmitFailed
        expr: radius_last_run_success == 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: UniFi RADIUS retransmit remediation failed

      - alert: UnifiRadiusRetransmitSwitchFailures
        expr: radius_switches_failed > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: One or more UniFi switches failed remediation

      - alert: UnifiRadiusRetransmitStale
        expr: time() - radius_last_run_timestamp > 93600
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: UniFi RADIUS retransmit remediation has not completed in over 26 hours
```

## Parallelism

Ansible parallelism is controlled by `ansible.forks`. Start around `50` and raise carefully if the controller and network tolerate it.

For about 400 sites and hundreds of switches, this avoids a thread per site and lets Ansible handle SSH concurrency directly from one generated inventory.

## Notes

- `secrets/` is excluded from git and should contain all real password material.
- Delete `secrets/secrets.yaml` after encryption if it is still present.
- Delete `secrets/sites.csv` after encryption if it is still present.
- Switch passwords are passed through Ansible's dynamic inventory at runtime and are not written to `data/`.
- If SSH keys are later preferred, replace `ansible_password` inventory generation with key settings and remove passwords from the CSV.
- Grafana is included because it pairs naturally with Prometheus. If all you need is alerting, Prometheus plus Alertmanager is enough; Grafana can be kept only for dashboards.
