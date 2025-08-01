```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\fodhelper.exe") | columns ComputerName,tgt.process.user,tgt.process.cmdline
```


# Original Sigma Rule:
```yaml
title: Bypass UAC via Fodhelper.exe
id: 7f741dcf-fc22-4759-87b4-9ae8376676a2
status: test
description: Identifies use of Fodhelper.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes.
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/e491ce22-792f-11e9-8f5c-d46d6d62a49e.html
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1548.002/T1548.002.md
author: E.M. Anhaus (originally from Atomic Blue Detections, Tony Lambert), oscd.community
date: 2019-10-24
modified: 2021-11-27
tags:
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\fodhelper.exe'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Legitimate use of fodhelper.exe utility by legitimate user
level: high
```
