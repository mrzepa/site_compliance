# UniFi RADIUS Retransmit Remediation

Standalone daily job that:

1. Logs into one or more UniFi controllers.
2. Resolves configured site names to UniFi site IDs.
3. Pulls all switches in each matched site.
4. Uses SSH fan-out to run:

```text
radius default-config retransmit 10 timeout 30
```

The service is intentionally independent of the repo's compliance auditor code. It copies the small amount of UniFi controller client behavior it needs.

## Index

- [Requirements](#requirements)
- [Files](#files)
- [Setup](#setup)
- [Run](#run)
- [Native Operation](#native-operation)
- [Grafana Login](#grafana-login)
- [Production Access](#production-access)
- [Configuration Reference](#configuration-reference)
- [Metrics](#metrics)
- [Grafana Dashboard](#grafana-dashboard)
- [Parallelism](#parallelism)
- [Notes](#notes)

## Requirements

Core requirements for every install:

- Network access from the runtime host to the UniFi controller.
- Network access from the runtime host to every target switch on SSH port `22`.
- A UniFi controller account that can list sites and devices.
- Switch SSH enabled. The default username is set in `config/config.yaml`; site-specific username exceptions can be set in `secrets/sites.vault`.
- One switch SSH password per UniFi site.
- For Docker and native Linux/macOS Ansible mode, the UniFi site names in `secrets/sites.vault` must match the UniFi controller site display names.
- For Docker and native Linux/macOS Ansible mode, UniFi controller credentials are stored in `secrets/secrets.vault`.
- For Windows-native Python mode, UniFi controller credentials and site switch credentials are stored in `.env`.

Docker requirements:

- Docker Engine or Docker Desktop with Docker Compose v2.

Native Linux/macOS requirements:

- Python 3.11 or newer.
- OpenSSH client.
- `python3-venv` on Linux distributions that package venv separately.

Native Windows requirements:

- Windows 11 Enterprise or another supported Windows release with Python 3.11 or newer.
- No Docker, WSL, or Ansible is required for the Windows-native runner.
- Windows-native mode uses `.env` for secrets and Paramiko for SSH fan-out.

Ansible and `ansible-vault` requirements:

- Docker mode runs Ansible and `ansible-vault` inside the `radius` container.
- Native Linux/macOS mode runs Ansible and `ansible-vault` from the local Python virtual environment.
- Windows-native Python mode does not use Ansible or Ansible Vault.
- The default Ansible SSH connection is `paramiko`, so native password authentication does not require `sshpass`.

Monitoring and production access requirements:

- Grafana and Prometheus are included in `docker-compose.yml`.
- A production deployment should have a valid SSL/TLS certificate.
- Use Apache, Nginx, or IIS as a reverse proxy in front of Grafana for HTTPS access.
- Keep Prometheus `9090` and raw metrics `9108` internal-only unless there is a specific monitoring requirement to expose them.

## Files

- `config/config.yaml`: local runtime configuration, copied from `config/config.example.yaml`
- `config/secrets.example.yaml`: example UniFi controller secret template
- `config/sites.example.csv`: example site/password/username CSV template
- `secrets/secrets.vault`: ansible-vault encrypted UniFi controller credentials
- `secrets/sites.vault`: ansible-vault encrypted site/password/username CSV
- `secrets/.vault_pass`: local ansible-vault password file
- `ansible.cfg`: Ansible defaults
- `app/inventory.py`: dynamic Ansible inventory builder
- `playbooks/radius_default_config.yml`: switch SSH playbook
- `app/scheduler.py`: daily scheduler plus Prometheus metrics endpoint
- `app/windows_native.py`: Windows-native pure Python runner without Ansible
- `scripts/run-native.sh`: native Linux/macOS/WSL runner
- `deploy/systemd/`: Linux systemd templates
- `deploy/launchd/`: macOS launchd template
- `deploy/windows/`: optional WSL Task Scheduler helpers

## Setup

Run commands from the `unifi_radius_retransmit` folder.

Create the local working files for Docker or native Linux/macOS Ansible mode.

Linux/macOS:

```bash
mkdir -p secrets
cp config/sites.example.csv secrets/sites.csv
cp config/secrets.example.yaml secrets/secrets.yaml
cp config/config.example.yaml config/config.yaml
```

Windows PowerShell for Docker mode:

```powershell
New-Item -ItemType Directory -Force secrets
Copy-Item config/sites.example.csv secrets/sites.csv
Copy-Item config/secrets.example.yaml secrets/secrets.yaml
Copy-Item config/config.example.yaml config/config.yaml
```

For Windows-native Python mode, skip the `config/` and `secrets/` setup below and create `.env` from `.env.windows-native.example` instead.

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

The optional `username` column is for exceptions. Leave it blank to use `ssh.username` from `config/config.yaml`; set it only when that site uses a different switch SSH username:

```csv
site_name,password,username
Example Clinic,replace-with-switch-admin-password,
Legacy Clinic,replace-with-switch-admin-password,admin
```

Create the vault password file before encrypting any secret files. Ansible cannot create `secrets/secrets.vault` or `secrets/sites.vault` until `secrets/.vault_pass` exists:

Linux/macOS:

```bash
echo "replace-with-a-real-vault-password" > secrets/.vault_pass
chmod 600 secrets/.vault_pass
```

Windows PowerShell:

```powershell
Set-Content -Path secrets/.vault_pass -Value "replace-with-a-real-vault-password" -NoNewline
```

Choose Docker or native tooling for the remaining setup.

Docker:

```bash
docker compose build radius
```

Native Linux/macOS or WSL:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -r requirements.txt
source .venv/bin/activate
```

Windows-native Python:

```cmd
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements-windows-native.txt
copy .env.windows-native.example .env
```

Edit `.env` and put all Windows-native secrets there. The `.env` file is excluded from git.

Windows-native `.env` uses JSON values for controllers and sites:

```text
UNIFI_CONTROLLERS_JSON=[{"name":"controller-a","base_url":"https://192.0.2.10:8443","username":"readonly-admin@example.com","password":"change-me","mfa_secret":"","api_key":""}]
RADIUS_SITES_JSON=[{"site_name":"Example Clinic","password":"replace-with-switch-admin-password","username":""},{"site_name":"Legacy Clinic","password":"replace-with-switch-admin-password","username":"admin"}]
```

Do not create `secrets/*.vault` for the Windows-native runner; it does not use Ansible Vault. The vault steps below are only for Docker or native Linux/macOS Ansible mode.

Encrypt the UniFi controller secrets.

Linux/macOS:

```bash
ansible-vault encrypt secrets/secrets.yaml
mv secrets/secrets.yaml secrets/secrets.vault
```

Docker, Windows PowerShell:

```powershell
docker compose run --rm radius ansible-vault encrypt secrets/secrets.yaml
Rename-Item -Path secrets/secrets.yaml -NewName secrets.vault
```

Windows WSL:

```bash
ansible-vault encrypt secrets/secrets.yaml
mv secrets/secrets.yaml secrets/secrets.vault
```

Docker alternative:

```bash
docker compose run --rm radius ansible-vault encrypt secrets/secrets.yaml
mv secrets/secrets.yaml secrets/secrets.vault
```

Encrypt the site/password/username CSV.

Linux/macOS:

```bash
ansible-vault encrypt secrets/sites.csv
mv secrets/sites.csv secrets/sites.vault
```

Docker, Windows PowerShell:

```powershell
docker compose run --rm radius ansible-vault encrypt secrets/sites.csv
Rename-Item -Path secrets/sites.csv -NewName sites.vault
```

Windows WSL:

```bash
ansible-vault encrypt secrets/sites.csv
mv secrets/sites.csv secrets/sites.vault
```

Docker alternative:

```bash
docker compose run --rm radius ansible-vault encrypt secrets/sites.csv
mv secrets/sites.csv secrets/sites.vault
```

To edit either encrypted file later, use the same mode you used for setup.

Native:

```bash
ansible-vault edit secrets/sites.vault
ansible-vault edit secrets/secrets.vault
```

Docker:

```bash
docker compose run --rm radius ansible-vault edit secrets/sites.vault
docker compose run --rm radius ansible-vault edit secrets/secrets.vault
```

Ansible reads `secrets/.vault_pass` through `ansible.cfg`.

Before running Docker or native Linux/macOS Ansible mode, confirm these files exist:

- `config/config.yaml`
- `secrets/.vault_pass`
- `secrets/secrets.vault`
- `secrets/sites.vault`

## Run

Docker, Linux/macOS:

```bash
docker compose up -d --build
```

Docker, Windows PowerShell:

```powershell
docker compose up -d --build
```

Native, Linux/macOS/WSL:

```bash
source .venv/bin/activate
./scripts/run-native.sh
```

Windows-native Python:

```cmd
.\.venv\Scripts\python.exe -m app.windows_native --env-file .env
```

One-shot connectivity/remediation test without starting the scheduler:

Docker:

```bash
docker compose run --rm radius python -m app.run_once
```

Native Linux/macOS/WSL with Ansible:

```bash
source .venv/bin/activate
./scripts/run-once-native.sh
```

Windows PowerShell through WSL, only if you are using the WSL Ansible fallback:

```powershell
wsl.exe -d Ubuntu -- bash -lc "cd /opt/radius && export PYTHONPATH=$PWD && .venv/bin/python -m app.run_once"
```

If you are already inside the WSL shell:

```bash
cd /opt/radius
source .venv/bin/activate
./scripts/run-once-native.sh
```

Windows-native Python:

```cmd
.\.venv\Scripts\python.exe -m app.windows_native --env-file .env --once --no-metrics
```

The one-shot command still writes `data/last_run.json` and exits `0` on full success or `1` when any switch fails.

The remediation job runs on service start by default and then daily at `scheduler.daily_at` for Ansible mode or `RADIUS_DAILY_AT` for Windows-native Python mode.
The latest run summary is written to `data/last_run.json`. Its `completed_at` value is formatted as `YYYY-MM-DD HH:MM:SS TZ` using `scheduler.timezone` for Ansible mode or `RADIUS_TIMEZONE` for Windows-native Python mode.

Prometheus is available at `http://localhost:9090`.
Grafana is available at `http://localhost:3000`.
The job metrics endpoint is exposed at `http://localhost:9108/metrics`.

In native mode, the Python service exposes `http://localhost:9108/metrics`. Prometheus and Grafana are available only if you run them separately or keep the Compose monitoring services.

The Compose stack uses a dedicated Docker bridge network on `10.254.99.0/24` to avoid Docker auto-selecting a subnet that overlaps with production site networks.
If this subnet is changed after containers already exist, recreate the stack so Docker replaces the old network:

```bash
docker compose down
docker compose up -d --build
```

## Native Operation

Native Linux/macOS mode runs the same Python scheduler and Ansible playbook without Docker. Windows-native mode runs `app.windows_native` without Ansible. Keep either process running so the built-in scheduler can run daily.

Linux systemd:

1. Copy the project to `/opt/radius` or edit `deploy/systemd/radius.service` to match your install path.
2. Install dependencies with the native setup commands.
3. Install and start the service:

```bash
sudo cp deploy/systemd/radius.service /etc/systemd/system/radius.service
sudo systemctl daemon-reload
sudo systemctl enable --now radius.service
sudo systemctl status radius.service
```

The included `deploy/systemd/radius.timer` is optional. The service itself should stay running because `app.scheduler` owns the daily schedule.

macOS launchd:

1. Copy the project to `/opt/radius` or edit `deploy/launchd/com.example.radius.plist` to match your install path.
2. Install dependencies with the native setup commands.
3. Load the launch agent:

```bash
cp deploy/launchd/com.example.radius.plist ~/Library/LaunchAgents/com.example.radius.plist
launchctl load ~/Library/LaunchAgents/com.example.radius.plist
launchctl start com.example.radius
```

Windows without Docker or WSL:

Use the Windows-native Python runner. It does not use Ansible or Ansible Vault; it reads `.env`, discovers switches from the UniFi controller, and uses Paramiko to connect directly to each switch.

Install dependencies from inside `unifi_radius_retransmit`:

```cmd
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements-windows-native.txt
copy .env.windows-native.example .env
```

Edit `.env` with the real UniFi controller and site switch credentials:

```text
UNIFI_CONTROLLERS_JSON=[{"name":"controller-a","base_url":"https://192.0.2.10:8443","username":"readonly-admin@example.com","password":"change-me","mfa_secret":"","api_key":""}]
RADIUS_SITES_JSON=[{"site_name":"Example Clinic","password":"replace-with-switch-admin-password","username":""},{"site_name":"Legacy Clinic","password":"replace-with-switch-admin-password","username":"admin"}]
RADIUS_DEFAULT_USERNAME=switch-ssh-username
RADIUS_WORKERS=50
RADIUS_TIMEZONE=America/Toronto
RADIUS_RUN_ON_START=true
RADIUS_DAILY_AT=03:00
RADIUS_METRICS_PORT=9108
```

Leave `username` blank for sites that use `RADIUS_DEFAULT_USERNAME`. Set `username` only for site-level exceptions.

Run a one-shot test without starting the scheduler:

```cmd
.\.venv\Scripts\python.exe -m app.windows_native --env-file .env --once --no-metrics
```

Start the long-running scheduler:

```cmd
.\.venv\Scripts\python.exe -m app.windows_native --env-file .env
```

The Windows scheduled task should be created manually in the GUI. It starts the long-running native Python scheduler at boot. The Python scheduler controls the daily run time through `RADIUS_DAILY_AT`.

Manual Windows Task Scheduler setup:

1. Open **Task Scheduler**.
2. Select **Task Scheduler Library**.
3. Select **Create Task**, not **Create Basic Task**.
4. On **General**:
   - Name: `UniFi Radius Remediation`
   - Select **Run whether user is logged on or not** if this should run after reboot without a login session.
   - Select **Run with highest privileges** if your environment requires it.
5. On **Triggers**:
   - Select **New**.
   - Begin the task: **At startup**.
   - Select **OK**.
6. On **Actions**:
   - Select **New**.
   - Action: **Start a program**.
   - Program/script:

```text
C:\git\site_compliance\unifi_radius_retransmit\.venv\Scripts\python.exe
```

   - Add arguments:

```text
-m app.windows_native --env-file .env
```

   - Start in:

```text
C:\git\site_compliance\unifi_radius_retransmit
```

7. On **Settings**:
   - Enable **Allow task to be run on demand**.
   - Enable **If the task fails, restart every** and choose a retry interval such as `1 minute`.
8. Select **OK** and enter credentials if prompted.

To test the task from the GUI, right-click it and select **Run**. Check `data\last_run.json` in the project folder.

Windows WSL fallback:

If WSL is available on a different host later, the older WSL helper is still included:

```powershell
.\deploy\windows\register-radius-wsl-task.ps1 -Distro Ubuntu -WslProjectPath /opt/radius
```

## Troubleshooting

If `data/last_run.json` shows switches as `UNREACHABLE` with messages like `connect to host ... port 22: Connection timed out`, the UniFi lookup worked but the container cannot open SSH to the switch management IPs.

Test TCP connectivity to a switch from inside the same container network:

```bash
docker compose run --rm radius nc -vz -w 5 172.20.70.2 22
```

Test basic routing:

```bash
docker compose run --rm radius ping -c 4 172.20.70.2
```

Inspect the route table from inside the container:

```bash
docker compose run --rm radius ip route
```

Test SSH negotiation manually:

```bash
docker compose run --rm radius ssh -vvv -o ConnectTimeout=10 -o StrictHostKeyChecking=no switch-ssh-username@172.20.70.2
```

If these fail from inside the container but work from the host PC, check Docker Desktop, VPN split tunneling, firewall policy, routing to the switch management VLANs, and whether the switches actually allow SSH from the Docker host.

In native mode, run the same tools directly from the runtime host or WSL shell, for example `nc -vz -w 5 172.20.70.2 22`, `ping -c 4 172.20.70.2`, and `ip route`.

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
- `secrets/secrets.vault` for UniFi controller credentials
- `secrets/sites.vault` for site-specific switch passwords

Useful native/Docker SSH setting:

```yaml
ansible:
  connection: paramiko
```

Use `paramiko` for the most portable password-based SSH behavior. Use `ssh` only when the runtime host has OpenSSH plus the required password-auth support installed.

## Metrics

- `radius_last_run_success`
- `radius_last_run_timestamp`
- `radius_last_run_duration_seconds`
- `radius_switches_total`
- `radius_switches_failed`
- `radius_sites_missing`: count of configured site names that did not match any UniFi controller site during the last inventory lookup
- `radius_site_switches_total{site="..."}`
- `radius_site_switches_success{site="..."}`
- `radius_site_switches_failed{site="..."}`
- `radius_switch_status{site="...",switch="...",host="..."}`

## Grafana Dashboard

Grafana is provisioned automatically with:

- A Prometheus datasource pointing at `http://prometheus:9090`
- A `Radius Remediation` dashboard in the `Radius` folder
- A `Site` dropdown sourced from discovered sites
- A `Failed Connectivity Last Run` table for drilling into failed switches

The dashboard includes sites with failures, total targeted switches, failed switches, success rate, failed connectivity for the latest run, failures by site, per-switch status, run duration, and a count of configured sites not found in UniFi.

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
