```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults" and tgt.process.cmdline contains "http" and tgt.process.cmdline contains " 0"))
```


# Original Sigma Rule:
```yaml
title: IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols Via CLI
id: 10344bb3-7f65-46c2-b915-2d00d47be5b0
related:
    - id: 3fd4c8d7-8362-4557-a8e6-83b29cc0d724
      type: similar
status: test
description: |
    Detects changes to Internet Explorer's (IE / Windows Internet properties) ZoneMap configuration of the "HTTP" and "HTTPS" protocols to point to the "My Computer" zone. This allows downloaded files from the Internet to be granted the same level of trust as files stored locally.
references:
    - https://twitter.com/M_haggis/status/1699056847154725107
    - https://twitter.com/JAMESWT_MHT/status/1699042827261391247
    - https://learn.microsoft.com/en-us/troubleshoot/developer/browsers/security-privacy/ie-security-zones-registry-entries
    - https://www.virustotal.com/gui/file/339ff720c74dc44265b917b6d3e3ba0411d61f3cd3c328e9a2bae81592c8a6e5/content
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-09-05
tags:
    - attack.execution
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults'
            - 'http'
            - ' 0'
    condition: selection
falsepositives:
    - Unknown
level: high
```
