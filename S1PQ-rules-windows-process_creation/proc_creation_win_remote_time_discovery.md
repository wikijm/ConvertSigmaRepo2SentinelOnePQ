```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\\net.exe" or tgt.process.image.path contains "\\net1.exe") and tgt.process.cmdline contains "time") or (tgt.process.image.path contains "\\w32tm.exe" and tgt.process.cmdline contains "tz")))
```


# Original Sigma Rule:
```yaml
title: Discovery of a System Time
id: b243b280-65fe-48df-ba07-6ddea7646427
status: test
description: Identifies use of various commands to query a systems time. This technique may be used before executing a scheduled task or to discover the time zone of a target system.
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/fcdb99c2-ac3c-4bde-b664-4b336329bed2.html
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1124/T1124.md
author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
date: 2019-10-24
modified: 2022-06-28
tags:
    - attack.discovery
    - attack.t1124
logsource:
    category: process_creation
    product: windows
detection:
    selection_time:
        Image|endswith:
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains: 'time'
    selection_w32tm:
        Image|endswith: '\w32tm.exe'
        CommandLine|contains: 'tz'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of the system utilities to discover system time for legitimate reason
level: low
```
