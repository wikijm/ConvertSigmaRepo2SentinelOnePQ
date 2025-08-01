```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\sdclt.exe")
```


# Original Sigma Rule:
```yaml
title: Sdclt Child Processes
id: da2738f2-fadb-4394-afa7-0a0674885afa
status: test
description: A General detection for sdclt spawning new processes. This could be an indicator of sdclt being used for bypass UAC techniques.
references:
    - https://github.com/OTRF/detection-hackathon-apt29/issues/6
    - https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/3.B.2_C36B49B5-DF58-4A34-9FE9-56189B9DEFEA.md
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020-05-02
modified: 2021-11-27
tags:
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\sdclt.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
