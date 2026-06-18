# Bug Bounty Auto Recon

`bugBounty_auto_recon.py` is a robust, program-aware reconnaissance pipeline built for authorized security testing and bug bounty hunters. 

It reads scoped targets, discovers subdomains, tracks historical state using SQLite, and exclusively scans newly discovered hosts to save time and resources. All events are logged gracefully, and notifications are broadcasted seamlessly using ProjectDiscovery's `notify` utility.

Designed to be run repeatedly (via cron or systemd), this tool works completely headless.

> **Disclaimer:** Use this tool only on assets you own or are explicitly authorized to test.

---

## 🚀 Key Features

* **Stateful Execution (SQLite)**: Subdomains and vulnerabilities are logged locally. Only *new* subdomains undergo the intensive scanning pipeline (HTTP probing, port scanning, crawling, and vulnerability scanning).
* **Multi-Tool Pipeline**: 
  1. `subfinder`: Discovers subdomains.
  2. `httpx`: Identifies live web servers.
  3. `naabu`: Scans open ports and fingerprints services.
  4. `katana`: Crawls live URLs dynamically (Runs concurrently with Naabu).
  5. `nuclei`: Scans the combined deduplicated URLs for vulnerabilities.
* **Universal Notifications (`notify`)**: Replaced hardcoded Telegram support with ProjectDiscovery's `notify`. You can now receive alerts on Discord, Slack, Telegram, Teams, or custom webhooks.
* **Step-by-Step Alerts**: Configurable progress tracking. Receive individual alerts as each tool finishes its execution, followed by a beautifully formatted Markdown summary report.
* **Headless Service Ready**: Fully utilizes Python's `logging` module (no standard CLI `print()` noise) making it highly optimized to run as a Linux background service.
* **Automated Bootstrapping**: Rapidly onboard new target domains right from the CLI.

---

## 🛠️ Requirements

### Python
* Python 3.10+
* Only built-in standard library modules are used (no `pip install` required).

### External Tools
The following binaries must be installed and available in your system `$PATH`:
* [subfinder](https://github.com/projectdiscovery/subfinder)
* [httpx](https://github.com/projectdiscovery/httpx)
* [naabu](https://github.com/projectdiscovery/naabu)
* [katana](https://github.com/projectdiscovery/katana)
* [nuclei](https://github.com/projectdiscovery/nuclei)
* [notify](https://github.com/projectdiscovery/notify)

Install them easily via Go:
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
```

---

## ⚙️ Configuration (.env)

The script relies on a local `.env` file for configuration. Copy `.env.example` to `.env`.

```bash
cp .env.example .env
nano .env
```

### Key Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `ROOT_DIR` | The master directory where all databases, targets, logs, and artifacts are stored. | `recon_watch_data` |
| `NOTIFY_BIN` | Path to the `notify` binary. | `notify` |
| `NOTIFY_ID` | Optional provider ID configured in your `provider-config.yaml` to route messages. | *(Blank)* |
| `NOTIFY_STEP_BY_STEP` | If `true`, sends alerts after each tool finishes. If `false`, only sends a final summary. | `true` |
| `MAX_JOB_RETENTION_DAYS` | Automatically deletes tool output artifacts older than X days. | `30` |

*(All tool binaries and timeouts are also configurable in the `.env` file).*

---

## 🏗️ Setup & Usage

### 1. Initialize the Environment
Before running your first scan, initialize the core folder structure and SQLite database:

```bash
python3 bugBounty_auto_recon.py --setup
```
This creates the master `ROOT_DIR` (e.g., `recon_watch_data/`) along with the `targets/`, `work/`, `logs/`, and the empty `recon.db` database.

### 2. Add a Target
Easily bootstrap a new target domain into the pipeline:

```bash
python3 bugBounty_auto_recon.py -d example.com
```
This automatically formats the program name and creates `recon_watch_data/targets/example_com.txt` with your domain.

### 3. Run the Pipeline
Run the script to execute the full pipeline across all configured targets:

```bash
python3 bugBounty_auto_recon.py
```
*Note: If no domains exist in your `targets/` folder, the script will safely log an error and exit.*

---

## 📂 Data Storage & Artifacts

All data is sandboxed securely under your configured `ROOT_DIR`. 

```text
recon_watch_data/
├── recon.db                    # SQLite tracking database
├── logs/
│   └── recon_watch.log         # Headless service logs
├── targets/
│   ├── example_com.txt         # Program scope files
│   └── company_b.txt
└── work/                       # Artifacts (JSONL, TXT) generated per run
    └── example_com/
        └── 20260616_120000/
            ├── roots.txt
            ├── new_subdomains.txt
            ├── httpx_hosts.txt
            ├── naabu.jsonl
            ├── katana_crawled_urls.txt
            └── nuclei.jsonl
```

### Target Files Layout
If `targets/example_com.txt` contains multiple domains, they are scanned together as one overarching program.

```text
# Main production scope
example.com
example.net

# Secondary brand
api.example.org
```

---

## 📡 Notifications

The integration with `notify` enables highly formatted Markdown reports natively supported by platforms like Discord and Slack.

**Step-by-Step Reporting (`NOTIFY_STEP_BY_STEP=true`)**:
```text
[example_com] Step 1 - subfinder completed successfully
[example_com] Step 2 - httpx completed successfully
[example_com] Step 3 - naabu completed successfully
[example_com] Step 4 - katana completed successfully
[example_com] Step 5 - nuclei completed successfully
```

**Final Recon Summary**:
After execution, a detailed Markdown report is fired off containing:
* Program name and scope root count.
* Subfinder discovered / new / known host counts.
* HTTPX live host validation metrics.
* Naabu port & service result count.
* Katana newly crawled URL count.
* Nuclei vulnerability findings (grouped by severity).
* Detailed blocks featuring Live Host specifics (URL, Status, Tech Stack, Ports, and Vulns).

---

## 🐧 Linux Service Setup (Systemd)

Because this script tracks state and runs silently, it is perfect for automation via cron or systemd timers. 

**Example systemd service** (`/etc/systemd/system/recon-watch.service`):
```ini
[Unit]
Description=Bug Bounty Auto Recon Scan
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=recon
WorkingDirectory=/opt/recon-watch
Environment=PATH=/usr/local/bin:/usr/bin:/bin:/home/recon/go/bin
ExecStart=/usr/bin/python3 /opt/recon-watch/bugBounty_auto_recon.py
NoNewPrivileges=true
PrivateTmp=true
```

**Example systemd timer** (`/etc/systemd/system/recon-watch.timer`):
```ini
[Unit]
Description=Run Recon Watch hourly

[Timer]
OnCalendar=hourly
Persistent=true
Unit=recon-watch.service

[Install]
WantedBy=timers.target
```

Enable the automation:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now recon-watch.timer
```
