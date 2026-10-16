# Detection #1 — Path Enumeration (Single Source, Many Distinct Paths)

- **MITRE ATT&CK:** T1595.003 — Active Scanning: Wordlist Scanning
- **Severity:** Low
- **Data source:** nginx access logs (`cybersteps_web`, `sourcetype=nginx:access`)
- **Attack simulated:** `gobuster dir -u http://10.10.10.20 -w /usr/share/wordlists/dirb/common.txt -t 30 -q`

## SPL

```spl
index=cybersteps_web sourcetype="nginx:access"
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\"(?<method>[A-Z]+)\s(?<url>\S+)"
| rex "\"\s+(?<status>\d{3})\s"
| stats count as total_requests dc(url) as unique_paths
    count(eval(status=="404")) as not_found_count
    count(eval(status=="403")) as forbidden_count by src_ip
| eval not_found_ratio=round(not_found_count/total_requests*100, 1)
| where unique_paths > 50 AND not_found_ratio > 70
| sort -total_requests
```

Note: nginx fields are extracted at search time with `rex` because no nginx add-on is installed.

## Threshold

`unique_paths > 50 AND not_found_ratio > 70`

## False positives

Internal vulnerability scanners, uptime/health monitors, legitimate crawlers, or a broken application link generating many organic 404s.

## Triage

1. Is `src_ip` a known internal scanner or an unexpected address? (`10.10.10.40` is the Kali attacker.)
2. Did any request return 200 (a successful hit worth investigating), or did the IP pivot to POSTs after mapping?

## Evidence (verified Oct 2026)

Gobuster from `10.10.10.40`: 4,576 × 404, 34 × 403 (honeypot paths), 5 × 200, user agent `gobuster/3.8.2` — 99.9% non-success from one source.
