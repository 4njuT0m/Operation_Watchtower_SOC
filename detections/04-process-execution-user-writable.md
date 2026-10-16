# Detection #4 — Process Execution from User-Writable Location

- **MITRE ATT&CK:** T1036.005 — Masquerading: Match Legitimate Name or Location
- **Severity:** High
- **Data source:** Sysmon EventCode 1 (`cybersteps_windows`, `sourcetype=XmlWinEventLog source=*Sysmon*`)
- **Attack simulated:** `calc.exe` copied to `C:\Users\Public\svchost.exe` and run from PowerShell.

## SPL

```spl
index=cybersteps_windows sourcetype="XmlWinEventLog" source="*Sysmon*" EventCode=1
| search Image="*\\Users\\Public\\*"
| table _time, Image, CommandLine, ParentImage, User
| sort -_time
```

## Threshold

Any process whose `Image` path contains `\Users\Public\`.

## False positives

Some legitimate software installers temporarily drop helper binaries into Public or Temp folders; portable apps running from user profiles.

## Triage

1. Check the `Image` hash (in the Sysmon XML) against VirusTotal — a known-good renamed system binary (`calc.exe`), a known-bad tool, or unknown?
2. Read `ParentImage` — `powershell.exe` or `cmd.exe` as parent indicates scripted execution; a browser or email client as parent indicates exploitation or phishing delivery.

## Evidence (verified Oct 2026)

Sysmon EventCode 1: `Image = C:\Users\Public\svchost.exe`, but `OriginalFileName = CALC.EXE` and `Description = Windows Calculator` — a renamed binary. `ParentImage = powershell.exe`.
