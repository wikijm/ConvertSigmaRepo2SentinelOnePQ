```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline contains "Get-Clipboard")
```


# Original Sigma Rule:
```yaml
title: PowerShell Get-Clipboard Cmdlet Via CLI
id: b9aeac14-2ffd-4ad3-b967-1354a4e628c3
related:
    - id: 4cbd4f12-2e22-43e3-882f-bff3247ffb78
      type: derived
status: test
description: Detects usage of the 'Get-Clipboard' cmdlet via CLI
references:
    - https://github.com/OTRF/detection-hackathon-apt29/issues/16
    - https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/3.B.2_C36B49B5-DF58-4A34-9FE9-56189B9DEFEA.md
author: Nasreddine Bencherchali (Nextron Systems)
date: 2020-05-02
modified: 2022-12-25
tags:
    - attack.collection
    - attack.t1115
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'Get-Clipboard'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
