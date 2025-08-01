```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\at.exe" and tgt.process.cmdline contains "interactive"))
```


# Original Sigma Rule:
```yaml
title: Interactive AT Job
id: 60fc936d-2eb0-4543-8a13-911c750a1dfc
status: test
description: Detects an interactive AT job, which may be used as a form of privilege escalation.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1053.002/T1053.002.md
    - https://eqllib.readthedocs.io/en/latest/analytics/d8db43cf-ed52-4f5c-9fb3-c9a4b95a0b56.html
author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
date: 2019-10-24
modified: 2021-11-27
tags:
    - attack.privilege-escalation
    - attack.t1053.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\at.exe'
        CommandLine|contains: 'interactive'
    condition: selection
falsepositives:
    - Unlikely (at.exe deprecated as of Windows 8)
level: high
```
