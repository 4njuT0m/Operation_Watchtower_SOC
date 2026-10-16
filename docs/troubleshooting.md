# Troubleshooting Notes — Operation Watchtower

Real problems hit during the build and how they were fixed.

## Linux forwarder shipped zero logs

The forwarder service account (`splunkfwd`) had no read access to `/var/log`. Adding it to the `adm` group fixed it:

```bash
sudo usermod -aG adm splunkfwd
```

The systemd unit also grants `CAP_DAC_READ_SEARCH`; the `adm` group is the explicit, narrower permission.

## Sysmon data arrived as binary garbage (`\x00\x00...`)

A `monitor://` input was reading the `.evtx` file as plain text. Switched to the Windows Event Log API:

```
WinEventLog://Microsoft-Windows-Sysmon/Operational
```

## Sysmon searches returned nothing despite data arriving

The Splunk Add-on for Windows normalizes the sourcetype to `XmlWinEventLog` and stores the channel in the `source` field — the configured full sourcetype label is never stored. All Sysmon searches use:

```spl
sourcetype="XmlWinEventLog" source="*Sysmon*"
```

Also, the forwarder account (`NT SERVICE\SplunkForwarder`) needed to be in the **Event Log Readers** local group to read the Sysmon channel.

## Windows forwarder install failed (MSI error 1603)

A leftover product registration from a previous failed install made the MSI attempt a repair instead of a clean install. Removed the stale package and reinstalled silently:

```powershell
Uninstall-Package <name>
msiexec /i splunkforwarder.msi /qn ...
```

(MSI log line 2898 is an informational message, not the failure — the fatal code was 1603.)

## cybersteps_linux and cybersteps_web indexes missing from the receiver

After `clean eventdata`, the data was cleared but the index config entries were gone. Recreated them:

```
splunk add index cybersteps_linux
splunk add index cybersteps_web
```

## nginx logs not landing in cybersteps_web

The CyberSteps portal writes to `/var/log/nginx/cybersteps_access.log`, not the standard `access.log`. Updated `inputs.conf` to monitor the portal-specific path.

## SMB brute force — tool compatibility

Hydra's SMB module and crackmapexec/nxc could not authenticate against Windows 11 SMBv3 signing (`invalid reply` / `NETBIOS connection timed out`). Only impacket's `SMBConnection` authenticated cleanly and generated the 4625 events. Port 445 was initially filtered — enabled the "File and Printer Sharing (SMB-In)" rule — and failed-logon auditing was off (`auditpol /set /subcategory:"Logon" /failure:enable`).
