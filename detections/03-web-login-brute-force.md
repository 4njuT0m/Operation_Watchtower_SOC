# Detection #3 — Web Login Brute Force: Repeated POST to Login Endpoint

- **MITRE ATT&CK:** T1110.003 — Brute Force: Password Spraying
- **Severity:** High
- **Data source:** nginx access logs (`cybersteps_web`, `sourcetype=nginx:access`)
- **Attack simulated:** Hydra flood of `POST /api/auth/login` from Kali.

## SPL

```spl
index=cybersteps_web sourcetype="nginx:access"
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\"(?<method>[A-Z]+)\s(?<url>\S+)"
| search method=POST url="/api/auth/login"
| stats count by src_ip
| where count > 20
| sort -count
```

## Threshold

`count > 20` POST requests to `/api/auth/login` from one `src_ip`.

## False positives

Legitimate load-testing tools, broken application retry loops, or multiple users behind one NAT/proxy IP inflating the count.

## Triage

1. Is `src_ip` external or an unexpected address?
2. Did any POST return a different outcome than the rest? **Note:** this portal returns an identical `204 No Content` for every login, so success cannot be read from the response — the detection keys on request *volume* from one source, not on login success.

## Evidence (verified Oct 2026)

From `10.10.10.40`: 353 POSTs to `/api/auth/login`, user agent `Mozilla/5.0 (Hydra)`, all `204`. Hydra's "175 valid" was a false positive — `175` is the wordlist length, because `F=incorrect` never matched the empty 204 response.
