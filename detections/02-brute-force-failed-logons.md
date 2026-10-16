# Detection #2 — Brute Force: Repeated Failed Logons

- **MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing
- **Severity:** High
- **Data source:** Windows Security log, EventCode 4625 (`cybersteps_windows`)
- **Attack simulated:** impacket SMB authentication attempts against `Administrator@10.10.10.30` from Kali.

## SPL

```spl
index=cybersteps_windows EventCode=4625
| eval target_user=mvindex(Account_Name,1)
| stats count by Source_Network_Address, target_user
| where count > 10
| sort -count
```

Note: 4625 events carry two `Account_Name` values (the requester, then the target). Use `mvindex(Account_Name,1)` to get the account that was actually targeted.

## Threshold

`count > 10` failed logons (EventCode 4625) from one source.

## False positives

A user with stale credentials on a mapped drive or scheduled task; a misconfigured service retrying bad credentials; account-lockout retry loops.

## Triage

1. Is `Source_Network_Address` a known internal host or an unexpected/external address?
2. **Key question:** did an EventCode 4624 (successful logon) from the same source follow the 4625 failures? Failures then a success indicates likely credential compromise.

## Evidence (verified Oct 2026)

From `10.10.10.40` against Administrator: 233 failed logons = 68 "bad password" then 165 "account locked out". The lockout policy stopped the brute force; Administrator was never compromised. No 4624 success for Administrator from that source.
