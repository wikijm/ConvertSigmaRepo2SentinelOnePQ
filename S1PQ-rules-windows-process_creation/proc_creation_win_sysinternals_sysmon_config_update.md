```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\Sysmon64.exe" or tgt.process.image.path contains "\Sysmon.exe") or tgt.process.displayName="System activity monitor") and (tgt.process.cmdline contains "-c" or tgt.process.cmdline contains "/c" or tgt.process.cmdline contains "–c" or tgt.process.cmdline contains "—c" or tgt.process.cmdline contains "―c")))
```


# Original Sigma Rule:
```yaml
title: Sysmon Configuration Update
id: 87911521-7098-470b-a459-9a57fc80bdfd
status: test
description: Detects updates to Sysmon's configuration. Attackers might update or replace the Sysmon configuration with a bare bone one to avoid monitoring without shutting down the service completely
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-03-09
modified: 2024-03-13
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_pe:
        - Image|endswith:
              - \Sysmon64.exe
              - \Sysmon.exe
        - Description: 'System activity monitor'
    selection_cli:
        CommandLine|contains|windash: '-c'
    condition: all of selection_*
falsepositives:
    - Legitimate administrators might use this command to update Sysmon configuration.
level: medium
```
