```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains " msiexec" and tgt.process.cmdline contains "://"))
```


# Original Sigma Rule:
```yaml
title: MsiExec Web Install
id: f7b5f842-a6af-4da5-9e95-e32478f3cd2f
related:
    - id: 8150732a-0c9d-4a99-82b9-9efb9b90c40c
      type: similar
status: test
description: Detects suspicious msiexec process starts with web addresses as parameter
references:
    - https://blog.trendmicro.com/trendlabs-security-intelligence/attack-using-windows-installer-msiexec-exe-leads-lokibot/
author: Florian Roth (Nextron Systems)
date: 2018-02-09
modified: 2022-01-07
tags:
    - attack.defense-evasion
    - attack.t1218.007
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - ' msiexec'
            - '://'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
```
