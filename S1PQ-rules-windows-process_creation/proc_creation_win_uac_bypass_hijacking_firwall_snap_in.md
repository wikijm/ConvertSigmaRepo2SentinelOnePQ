```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\mmc.exe" and src.process.cmdline contains "WF.msc") and (not tgt.process.image.path contains "\\WerFault.exe")))
```


# Original Sigma Rule:
```yaml
title: UAC Bypass via Windows Firewall Snap-In Hijack
id: e52cb31c-10ed-4aea-bcb7-593c9f4a315b
status: test
description: Detects attempts to bypass User Account Control (UAC) by hijacking the Microsoft Management Console (MMC) Windows Firewall snap-in
references:
    - https://www.elastic.co/guide/en/security/current/uac-bypass-via-windows-firewall-snap-in-hijack.html#uac-bypass-via-windows-firewall-snap-in-hijack
author: Tim Rauch, Elastic (idea)
date: 2022-09-27
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1548
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\mmc.exe'
        ParentCommandLine|contains: 'WF.msc'
    filter:
        Image|endswith: '\WerFault.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
```
