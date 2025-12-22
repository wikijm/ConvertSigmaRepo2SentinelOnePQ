```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "sdclt.exe" and (tgt.process.integrityLevel in ("High","S-1-16-12288"))))
```


# Original Sigma Rule:
```yaml
title: Potential UAC Bypass Via Sdclt.EXE
id: 40f9af16-589d-4984-b78d-8c2aec023197
status: test
description: A General detection for sdclt being spawned as an elevated process. This could be an indicator of sdclt being used for bypass UAC techniques.
references:
    - https://github.com/OTRF/detection-hackathon-apt29/issues/6
    - https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/3.B.2_C36B49B5-DF58-4A34-9FE9-56189B9DEFEA.md
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020-05-02
modified: 2024-12-01
tags:
    - attack.privilege-escalation
    - attack.defense-evasion
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 'sdclt.exe'
        IntegrityLevel:
            - 'High'
            - 'S-1-16-12288' # High
    condition: selection
falsepositives:
    - Unknown
level: medium
```
