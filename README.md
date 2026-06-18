# Recon Watch Multi

`bugBounty_auto_recon.py` is a program-aware reconnaissance pipeline for authorized security testing and bug bounty work.

It reads scoped targets from text files, discovers subdomains, tracks state in SQLite, scans only newly discovered hosts through the follow-up tools, stores artifacts, and sends a clean Telegram summary for every program run.

Use this only on assets you own or are explicitly authorized to test.

## What The Script Does

For each enabled program, the script runs one complete scan cycle:

1. Reads scope roots from `targets/*.txt`.
2. Runs `subfinder` against the scope roots.
3. Compares discovered subdomains against the SQLite database.
4. Marks already-known hosts as seen.
5. Sends a Telegram summary even when nothing new is found.
6. If new subdomains exist, runs:
   - `httpx` to detect live web services.
   - `gowitness` optionally as a screenshot fallback.
   - `naabu -sV` to collect open ports and service/version data.
   - `nuclei` against live URLs.
7. Stores scan results, artifacts, and run metadata.
8. Sends one combined Telegram summary per program.

The script does not run forever. It executes once and exits. Use a Linux service manager such as `systemd` with a timer to run it hourly or on your preferred schedule.

## Important Behavior

- One file in `targets/` equals one program.
- Multiple domains in the same target file are treated as one company/program.
- SQLite is the source of truth for comparisons.
- The script does not require or call `ANEW`.
- Follow-up scans are performed only for newly discovered subdomains.
- If no new subdomains are found, Telegram still receives a summary showing zero new results.
- Telegram notifications are combined per program, not one message per host.
- Large Telegram reports are split into numbered parts automatically.
- Secrets are read from `.secret` or environment variables, not from the main Python file.

## Repository Files

```text
.
|-- bugBounty_auto_recon.py    Main scanner script
|-- .secret                 Local secrets file, ignored by git
|-- .secret.example         Example secrets file
|-- .gitignore              Ignore rules for secrets and Python cache files
|-- README.md               This documentation
`-- requirements.txt        Python dependency note
```

The script creates these runtime paths by default:

```text
targets/                    Input scope files
recon.db                    SQLite database
work/                       Per-program scan artifacts
logs/recon_watch.log        Runtime logs
```

## Requirements

### Python

- Python 3.10 or newer is recommended.
- No third-party Python packages are required.
- The script uses Python standard library modules only.

Install/check Python:

```bash
python3 --version
```

Optional virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` intentionally contains no package dependencies.

### External Tools

The following command-line tools must be installed and available in `PATH`, unless you pass custom binary paths with command-line arguments.

Required:

- `subfinder`
- `httpx`
- `naabu`
- `nuclei`

Optional:

- `gowitness`, used only as a best-effort screenshot fallback.

Common installation approach for ProjectDiscovery tools:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Make sure Go's binary directory is in `PATH`:

```bash
export PATH="$PATH:$HOME/go/bin"
```

Verify tools:

```bash
subfinder -version
httpx -version
naabu -version
nuclei -version
```

## Setup

Clone or copy the script into a working directory:

```bash
mkdir -p /opt/recon-watch
cd /opt/recon-watch
```

Create required directories:

```bash
mkdir -p targets work logs
```

Create the secrets file:

```bash
cp .secret.example .secret
nano .secret
chmod 600 .secret
```

`.secret` format:

```bash
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

Environment variables override `.secret`:

```bash
export TELEGRAM_BOT_TOKEN="your_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"
```

You can also point to a different secrets file:

```bash
export RECON_SECRET_FILE=/etc/recon-watch/secret.env
```

## Targets Layout

Create one text file per program in `targets/`.

Example:

```text
targets/
|-- company_a.txt
|-- company_b.txt
`-- internal_lab.txt
```

Each file contains root domains or scope roots, one per line:

```text
example.com
example.net
api.example.org
```

Blank lines and lines starting with `#` are ignored:

```text
# Main production scope
example.com

# Secondary brand
example.net
```

If `targets/company_a.txt` contains multiple domains, they are scanned together as one program named `company_a`.

## Running Manually

Basic run:

```bash
python3 bugBounty_auto_recon.py
```

Custom paths:

```bash
python3 bugBounty_auto_recon.py \
  --targets-dir /opt/recon-watch/targets \
  --db /opt/recon-watch/recon.db \
  --workdir /opt/recon-watch/work \
  --log-file /opt/recon-watch/logs/recon_watch.log \
  --secret-file /opt/recon-watch/.secret
```

Custom tool paths:

```bash
python3 bugBounty_auto_recon.py \
  --subfinder-bin /usr/local/bin/subfinder \
  --httpx-bin /usr/local/bin/httpx \
  --naabu-bin /usr/local/bin/naabu \
  --nuclei-bin /usr/local/bin/nuclei \
  --gowitness-bin /usr/local/bin/gowitness
```

Custom nuclei severities:

```bash
python3 bugBounty_auto_recon.py --nuclei-severities medium,high,critical
```

## Linux Service Setup

The script is designed to be run by a service or timer. It does not contain an internal infinite loop.

Example service file:

```ini
# /etc/systemd/system/recon-watch.service
[Unit]
Description=Recon Watch Multi scan
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=recon
Group=recon
WorkingDirectory=/opt/recon-watch
Environment=PATH=/usr/local/bin:/usr/bin:/bin:/home/recon/go/bin
ExecStart=/usr/bin/python3 /opt/recon-watch/bugBounty_auto_recon.py \
  --targets-dir /opt/recon-watch/targets \
  --db /opt/recon-watch/recon.db \
  --workdir /opt/recon-watch/work \
  --log-file /opt/recon-watch/logs/recon_watch.log \
  --secret-file /opt/recon-watch/.secret

NoNewPrivileges=true
PrivateTmp=true
```

Example timer file:

```ini
# /etc/systemd/system/recon-watch.timer
[Unit]
Description=Run Recon Watch Multi hourly

[Timer]
OnCalendar=hourly
Persistent=true
Unit=recon-watch.service

[Install]
WantedBy=timers.target
```

Enable and start the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now recon-watch.timer
```

Run a scan immediately:

```bash
sudo systemctl start recon-watch.service
```

Check status and logs:

```bash
systemctl status recon-watch.service
journalctl -u recon-watch.service -n 100 --no-pager
```

List timer status:

```bash
systemctl list-timers recon-watch.timer
```

## Telegram Summary Format

Each program run sends one combined Telegram report.

When new subdomains are found, the message includes:

- Program name.
- Scan time.
- Scope root count.
- Artifact directory.
- Subfinder discovered/new/known counts.
- HTTPX checked/live counts.
- Naabu port/service result count.
- Nuclei finding count grouped by severity.
- New subdomain list.
- Live host details with URL, status, title, tech, ports, and nuclei summary.
- New non-live subdomain list.

When no new subdomains are found, the script still sends a summary like:

```text
Recon Summary
Program: company_a
Subfinder: 153 discovered, 0 new, 153 already known
HTTPX: 0 checked, 0 live
Naabu: 0 port/service result(s)
Nuclei: 0 finding(s)
New subdomains: none
```

## Data Storage

SQLite database:

```text
recon.db
```

Main tables:

- `programs`: one row per target file/program.
- `scope_domains`: root domains for each program.
- `subdomains`: discovered hosts and latest state.
- `httpx_results`: historical HTTP probing output.
- `ports`: historical naabu output.
- `nuclei_findings`: historical nuclei findings.
- `artifacts`: screenshots and other generated files.
- `runs`: per-program scan run summaries.

The database uses `program_id` to keep programs separated.

Artifacts are written under:

```text
work/<program_name>/<timestamp>/
```

Example:

```text
work/company_a/20260616_120000/
|-- roots.txt
|-- new_subdomains.txt
|-- httpx_hosts.txt
|-- httpx.jsonl
|-- naabu_hosts.txt
|-- naabu.jsonl
|-- nuclei_urls.txt
`-- nuclei.jsonl
```

## Command-Line Options

```text
--targets-dir          Directory with one .txt file per program
--db                   SQLite database path
--workdir              Artifact output directory
--log-file             Log file path
--secret-file          KEY=VALUE secrets file path
--subfinder-bin        subfinder executable path/name
--httpx-bin            httpx executable path/name
--naabu-bin            naabu executable path/name
--nuclei-bin           nuclei executable path/name
--gowitness-bin        gowitness executable path/name
--nuclei-severities    Comma-separated nuclei severities
```

Environment variable equivalents:

```text
RECON_SECRET_FILE
TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID
SUBFINDER_BIN
HTTPX_BIN
NAABU_BIN
NUCLEI_BIN
GOWITNESS_BIN
NUCLEI_SEVERITIES
```

## Workflow Details

### Target Sync

At the start of each run, the script scans `targets/*.txt`.

For each target file:

- Filename stem becomes the program name.
- File contents become scope roots.
- Existing program rows are updated.
- Scope roots are refreshed in the database.

If a target file disappears, the old program is not automatically deleted.

### Subdomain Discovery

The script writes the program roots to:

```text
work/<program>/<timestamp>/roots.txt
```

Then it runs:

```bash
subfinder -dL roots.txt -silent
```

Subfinder output is parsed into a unique set of hosts.

### New Host Detection

The script compares discovered hosts against the `subdomains` table.

- New hosts are inserted.
- Existing hosts get `last_seen` updated.
- Only new hosts continue to `httpx`, `naabu`, and `nuclei`.

### HTTPX

For new hosts, the script runs:

```bash
httpx -l httpx_hosts.txt -json -sc -title -td -server -ip -cname -no-color -silent -o httpx.jsonl
```

It stores status code, title, detected technology, server, IP, CNAME, URL, and raw JSON.

### Screenshots

The script checks whether `httpx` output includes any screenshot-like path field.

If no screenshot is found and `gowitness` is installed, it tries one best-effort fallback screenshot for a live host.

### Naabu

For live hosts, the script runs:

```bash
naabu -list naabu_hosts.txt -sV -json -silent -o naabu.jsonl
```

It stores host, IP, port, protocol, service, version, and raw JSON.

Note: the script uses `naabu -sV`. It does not call a separate `nmap` command.

### Nuclei

For live URLs, the script runs:

```bash
nuclei -l nuclei_urls.txt -severity medium,high,critical -json -silent -no-color -o nuclei.jsonl
```

The severity list can be changed with:

```bash
--nuclei-severities low,medium,high,critical
```

## Security Notes

- Keep `.secret` private.
- Use `chmod 600 .secret`.
- Do not commit `.secret`.
- Rotate a bot token if it was ever placed in source code, logs, screenshots, or chat.
- Run the service as a dedicated low-privilege user.
- Keep target files limited to authorized scope.
- Review tool output before reporting findings externally.

## Troubleshooting

### No Telegram Message

Check:

```bash
cat .secret
systemctl status recon-watch.service
journalctl -u recon-watch.service -n 100 --no-pager
```

Verify that the bot token and chat ID are correct, and that the host can reach:

```text
https://api.telegram.org
```

### Tools Not Found

Check:

```bash
which subfinder
which httpx
which naabu
which nuclei
```

If running under `systemd`, remember that the service `PATH` may be different from your shell.

Use absolute paths or set `Environment=PATH=...` in the service.

### No New Hosts Are Scanned Further

This is expected.

The script only runs `httpx`, `naabu`, and `nuclei` on newly discovered subdomains. Existing hosts are updated as seen, but are not rescanned by default.

### Target File With Multiple Domains

This is supported.

All domains in one target file are treated as one program and passed together to `subfinder`.

### Database Gets Large

Historical `httpx`, `ports`, and `nuclei_findings` rows are appended over time. Add your own retention policy or periodic cleanup if needed.

## Exit Codes

- `0`: scan completed successfully.
- `1`: scan failed or timed out.

This makes the script suitable for monitoring with `systemd`.

