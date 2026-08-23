# SPL Query Library

These are the 8 queries I built during the project against real lab data. I keep them here because I reuse most of them when troubleshooting or investigating something.

All queries run against the cybersteps_* indexes. Adjust the time range in Splunk's time picker — most of these I run over Last 24 hours or Last 7 days depending on what I'm looking at.

---

## 1. All WINCL1 events as a table

```spl
index=cybersteps_windows host=WINCL1 earliest=-24h
| table _time, host, sourcetype, EventCode
```

Good for a quick look at what the Windows box reported today. I usually run this first when I open Splunk.

---

## 2. Event count by sourcetype across all indexes

```spl
index=cybersteps_*
| stats count by sourcetype
```

This is my pipeline health check. If a sourcetype is missing or the count drops suddenly, something stopped forwarding.

---

## 3. Top 10 EventCodes from WINCL1

```spl
index=cybersteps_windows host=WINCL1
| top limit=10 EventCode
```

Useful for understanding normal behaviour on the endpoint. Once you know what's normal, anomalies stand out.

---

## 4. WEB1 auth.log sorted by time

```spl
index=cybersteps_linux host=web1 source="/var/log/auth.log"
| sort _time
```

Chronological view of authentication on the web server. First thing I check when investigating a suspected login attempt.

---

## 5. Nginx access events by hour

```spl
index=cybersteps_web sourcetype="nginx:access"
| timechart span=1h count
```

Shows traffic volume over time. A sudden spike means something automated is hitting the portal.

---

## 6. Find "failed" in Linux logs

```spl
index=cybersteps_linux failed
```

Quick triage for failed logins and sudo failures. Simple but effective for a first look.

---

## 7. Unique hostnames seen in last 7 days

```spl
index=cybersteps_* earliest=-7d
| dedup host
| table host
```

Confirms which machines are actually reporting. If a host disappears from this list, the forwarder is down.

---

## 8. Add day of week with eval

```spl
index=cybersteps_*
| eval day_of_week=strftime(_time, "%A")
| table _time, host, day_of_week
```

I use this when investigating off-hours activity. Seeing "Sunday 3am" next to an event tells a story that a timestamp alone doesn't.

---

## Note on nginx field extraction

The CyberSteps portal nginx logs don't auto-extract fields — no Splunk add-on for nginx is installed. All web queries need rex to pull out src_ip, method, url and status before you can filter or group on them:

```spl
index=cybersteps_web sourcetype="nginx:access"
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\"(?<method>[A-Z]+)\s(?<url>\S+)"
| rex "\"\s+(?<status>\d{3})\s"
```

## Note on Sysmon sourcetype

The Splunk Windows TA normalizes Sysmon events. The sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` is never stored — use this instead:

```spl
sourcetype="XmlWinEventLog" source="*Sysmon*"
```
