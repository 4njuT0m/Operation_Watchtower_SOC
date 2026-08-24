# Operation Watchtower

A home lab SOC I built from scratch over two weeks. Started with nothing — no logs, no alerts, no visibility into what was happening on the machines. By the end I had a working Splunk environment collecting logs from a Windows endpoint and a Linux web server, five live detections mapped to MITRE ATT&CK, and a full attack campaign I ran myself and caught using the system I built.

---

## The setup

Four VMs on VMware Workstation, all on the same NAT network — `10.10.10.0/24`.

| Machine | IP | What it does |
|---|---|---|
| SOC-HOST | 10.10.10.5 | Splunk Enterprise — receives logs, indexes them, runs searches and alerts |
| WEB1 | 10.10.10.20 | Ubuntu web server running the CyberSteps internal portal. Ships logs via Universal Forwarder |
| WINCL1 | 10.10.10.30 | Windows 11 endpoint with Sysmon installed. Ships event logs via Universal Forwarder |
| Kali | 10.10.10.40 | Attacker — gobuster, Hydra, crackmapexec, impacket |

WEB1 is a full clone of the SOC-HOST Ubuntu server, renamed and given a separate IP. Kali has a static IP set via NetworkManager because the DHCP lease kept dropping between reboots.

Logs flow like this:

```
WEB1 (forwarder) ──┐
                   ├──► SOC-HOST :9997 ──► indexes ──► searches / alerts / dashboards
WINCL1 (forwarder)─┘

Kali ──► attacks WEB1 and WINCL1 ──► that traffic is what the detections catch
```

---

## Indexes

Three indexes on SOC-HOST. Separated by data type so searches are fast and don't scan stuff they don't need to.

| Index | What's in it |
|---|---|
| `cybersteps_linux` | WEB1 syslog and auth.log |
| `cybersteps_windows` | WINCL1 Security log, System log, Sysmon, PowerShell Script Block Logging |
| `cybersteps_web` | nginx access and error logs from the CyberSteps portal |

---

## Log sources

**WEB1** ships four sources:
- `/var/log/syslog` → `sourcetype=syslog` → `cybersteps_linux`
- `/var/log/auth.log` → `sourcetype=linux_secure` → `cybersteps_linux`
- `/var/log/nginx/cybersteps_access.log` → `sourcetype=nginx:access` → `cybersteps_web`
- `/var/log/nginx/cybersteps_error.log` → `sourcetype=nginx:error` → `cybersteps_web`

Worth noting: the CyberSteps portal writes to `cybersteps_access.log`, not the standard nginx `access.log`. Took a while to figure out why the web index was empty.

**WINCL1** ships four event log channels:
- `WinEventLog://Security`
- `WinEventLog://System`
- `WinEventLog://Microsoft-Windows-Sysmon/Operational`
- `WinEventLog://Microsoft-Windows-PowerShell/Operational`

All four go into `cybersteps_windows`.

One important thing about Sysmon: the Splunk Add-on for Windows (installed on SOC-HOST) normalizes the sourcetype. The configured label `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` is never actually stored — the TA strips it down to `XmlWinEventLog` and puts the channel name in the `source` field. Every Sysmon search in this project uses:

```spl
sourcetype="XmlWinEventLog" source="*Sysmon*"
```

Using the full sourcetype returns nothing.

---

## Detections

Five detections, all saved as live Splunk alerts, all tested against real attack traffic.

| # | Name | MITRE | Severity |
|---|---|---|---|
| 1 | Path Enumeration — Single Source, Many Distinct Paths | T1595.003 | Low |
| 2 | Brute Force — Repeated Failed Logons | T1110.001 | High |
| 3 | Web Login Brute Force — Repeated POST to Login Endpoint | T1110.003 | High |
| 4 | Process Execution from User-Writable Location | T1036.005 | High |
| 5 | Persistence — Scheduled Task Created | T1053.005 | Critical |

Full details — SPL queries, thresholds, false positive notes, triage steps — are in `/detections/`.

---

## Dashboards

Three dashboards in Splunk. Dashboard XML files are in `/dashboards/` if you want to import them.

**SOC Health** — pipeline health. Event counts per index, which hosts are reporting, volume over time, sourcetype breakdown. Open this first to check everything is working before you start looking at anything else.

**Detection Triage** — active threat visibility on the web portal. Scanner traffic, honeypot hits, login flood patterns, tool user-agents. Gobuster, Hydra and curl all show up by name in the user-agent table.

**Investigation** — Windows endpoint deep-dive. Brute force timeline, Sysmon process creation events, executions from user-writable paths, scheduled task creation. For reconstructing what actually happened during an incident.

---

## The attack I ran

Full kill chain from Kali against the lab:

**Reconnaissance** — gobuster directory scan against the portal. 4,615 requests in under 30 seconds. Hit 14 honeypot paths including `/.git/HEAD` and `/.htpasswd`. Detection #1 fired.

**Web credential access** — Hydra sprayed the portal login endpoint with a username wordlist and the password `admin123`. Found 175 valid combinations — the portal had weak default credentials across a lot of accounts. Detection #3 fired.

**Windows credential access** — this one took a few attempts to get working.

First tried Hydra against SMB:
```bash
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt 10.10.10.30 smb
```
Returned `invalid reply` immediately. Hydra's SMB module doesn't handle Windows 11's SMBv3 signing enforcement — it doesn't even get to an authentication attempt.

Switched to crackmapexec:
```bash
crackmapexec smb 10.10.10.30 -u Administrator -p /tmp/rockyou_custom.txt
```
crackmapexec connected and identified the target correctly (`signing:True`, `SMBv1:False`) but kept hitting `NETBIOS connection timed out` due to the same SMB signing issue. Generated some `STATUS_LOGON_FAILURE` events but unreliably.

Ended up writing a Python impacket script that uses `SMBConnection` directly — impacket handles SMBv3 signing natively, so each attempt hit Windows authentication cleanly. Generated 326 EventCode 4625 events. Detection #2 fired.

Before any of that worked, two things had to be fixed on WINCL1:
- Port 445 was filtered by the Windows firewall. Had to enable the SMB-In rule.
- Failed logon auditing was off by default. Had to run `auditpol /set /subcategory:"Logon" /failure:enable`.

**Execution** — copied `calc.exe` to `C:\Users\Public\svchost.exe` and ran it from PowerShell. Sysmon EventCode 1 caught it — `Image` shows the fake path, `ParentImage` shows `powershell.exe` launched it. Detection #4 fired.

**Persistence** — created a scheduled task called `WindowsUpdate` running `C:\Users\Public\update.exe` as SYSTEM at logon. EventCode 4698 recorded the creation. Detection #5 fired.

---

## What broke along the way

**Linux forwarder shipped zero logs** despite being correctly configured. The forwarder service account (`splunkfwd`) didn't have read access to `/var/log`. Adding it to the `adm` group fixed it.

**Sysmon data arrived as binary garbage** (`\x00\x00\x00...`). Was using `monitor://` on the `.evtx` file, which reads it as plain text. Switching to `WinEventLog://` fixed it — that uses the Windows Event Log API the way it's supposed to be used.

**Windows TA sourcetype normalization** — every Sysmon query returned nothing because the sourcetype I'd configured was being silently renamed by the TA during indexing. Took a while to figure out because the events were arriving, just under a different label.

**Windows forwarder install failed** with MSI error 2898/1603. A leftover product registration from a previous failed install made the MSI try to repair instead of doing a fresh install, and the repair path crashed on a UI font rendering issue. Fixed by removing the stale package with `Uninstall-Package` and reinstalling silently with `/qn`.

**Kali couldn't get a stable DHCP lease** after reboots. Set it to a static IP via `nmcli connection modify` instead.

**cybersteps_linux and cybersteps_web indexes were missing from the receiver** after running `clean eventdata`. The data had been cleaned but the index config entries were gone. Had to recreate them with `splunk add index`.

All of this is in `/docs/troubleshooting.md`.

---

## What's in this repo

```
configs/         inputs.conf for WEB1 and WINCL1, indexes.conf from SOC-HOST,
                 Sysmon config (SwiftOnSecurity base)

detections/      One file per detection — SPL, threshold, MITRE, FPs, triage

dashboards/      XML for all three Splunk dashboards. Import via:
                 Edit → Source tab in the dashboard editor

spl/             The eight SPL queries from the query library exercise

docs/            Lab setup, troubleshooting notes, full attack timeline

report/          Final PDF report

screenshots/     Evidence screenshots for each task and detection
```

---

## Tools used

- Splunk Enterprise 10.2.3
- Splunk Universal Forwarder 10.2.3 (Linux), 10.4.2 (Windows)
- Splunk Add-on for Microsoft Windows
- Sysmon 15.21 with SwiftOnSecurity config
- gobuster 3.8.2
- Hydra 9.7
- crackmapexec
- impacket (Python, SMBConnection)
- VMware Workstation

---

## Disclaimer

All attacks and tools in this repo were used against VMs I own, on an isolated VMware NAT network with no external exposure. Don't run any of this against systems you don't have permission to test.
