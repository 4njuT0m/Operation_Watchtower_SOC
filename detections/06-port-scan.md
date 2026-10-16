# Detection #6 — Network Service Discovery: Port Scan

- **MITRE ATT&CK:** T1046 — Network Service Discovery
- **Severity:** Medium
- **Data source:** Windows Filtering Platform audit events — EventCode 5156 (allowed) / 5157 (blocked) / 5152 (dropped), in the Security log (`cybersteps_windows`)
- **Attack simulated:** `nmap -sT -p 1-1000 10.10.10.30` (TCP connect scan from Kali)

## Setup

Windows Filtering Platform auditing is off by default. Enable it on WINCL1:

```cmd
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
```

These events flow through the existing `WinEventLog://Security` input — no new forwarder config. WFP auditing is high-volume, so enable it only while testing and disable it afterward.

## SPL

```spl
index=cybersteps_windows EventCode IN (5156,5157,5152)
| stats dc(Destination_Port) as ports_hit values(action) as action by Source_Address
| where ports_hit > 20
| sort -ports_hit
```

## Threshold

`> 20` distinct destination ports from one `Source_Address`.

## False positives

Vulnerability scanners, asset-discovery tools, or backup/monitoring agents that legitimately contact many ports.

## Triage

1. Is `Source_Address` a known scanner / asset-management host, or unexpected?
2. Did the scan precede a connection to an *open* port (follow-on exploitation)?

## Evidence (verified Oct 2026)

`Source_Address 10.10.10.40` contacted 1,000 distinct destination ports (actions: allowed, blocked, failure) in seconds — a clear port scan.
