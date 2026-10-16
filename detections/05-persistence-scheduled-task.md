# Detection #5 — Persistence: Scheduled Task Created

- **MITRE ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task
- **Severity:** Critical
- **Data source:** Windows Security log, EventCode 4698 (`cybersteps_windows`)
- **Attack simulated:** `schtasks /create /tn "WindowsUpdate" /tr "C:\Users\Public\update.exe" /sc onlogon /ru SYSTEM`

## SPL

```spl
index=cybersteps_windows sourcetype="WinEventLog" EventCode=4698
| table _time, host, Task_Name, Account_Name, Command
| sort -_time
```

Requires `auditpol /set /subcategory:"Other Object Access Events" /success:enable`.

## Threshold

Any result — one task creation is enough to investigate.

## False positives

Legitimate software installers and Windows Update commonly create scheduled tasks; IT admin scripts may create them at scale.

## Triage

1. Check `Task_Name` and `Command` — does the task run a binary from `C:\Users\Public\`, `%TEMP%`, or another user-writable path? That is immediate escalation.
2. Check `Account_Name` — a standard user creating a SYSTEM-level task is highly suspicious.

## Note — created vs updated

- **4698** = scheduled task *created*
- **4702** = scheduled task *updated* (an attacker modifying an existing task shows here, not 4698)

A thorough version catches both: `EventCode IN (4698, 4702)`.

## Evidence (verified Oct 2026)

`\WindowsUpdate` task running `C:\Users\Public\update.exe` as SYSTEM at logon.
