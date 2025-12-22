```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\schtasks.exe" and tgt.process.cmdline contains "/Create ") and (tgt.process.cmdline contains "/TN \"{" or tgt.process.cmdline contains "/TN '{" or tgt.process.cmdline contains "/TN {") and (tgt.process.cmdline contains "}\"" or tgt.process.cmdline contains "}'" or tgt.process.cmdline contains "} ")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Scheduled Task Name As GUID
id: ff2fff64-4cd6-4a2b-ba7d-e28a30bbe66b
status: test
description: Detects creation of a scheduled task with a GUID like name
references:
    - https://thedfirreport.com/2022/10/31/follina-exploit-leads-to-domain-compromise/
    - https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-31
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.t1053.005
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/Create '
    selection_tn:
        CommandLine|contains:
            # Can start with single or double quote
            - '/TN "{'
            - "/TN '{"
            - "/TN {"
    selection_end:
        CommandLine|contains:
            # Ending of the name to avoid possible FP in the rest of the commandline
            - '}"'
            - "}'"
            - '} '
    condition: all of selection_*
falsepositives:
    - Legitimate software naming their tasks as GUIDs
level: medium
```
