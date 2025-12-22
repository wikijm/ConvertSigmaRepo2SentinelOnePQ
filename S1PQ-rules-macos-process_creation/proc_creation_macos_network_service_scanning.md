```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (((tgt.process.image.path contains "/nc" or tgt.process.image.path contains "/netcat") and (not tgt.process.cmdline contains "l")) or (tgt.process.image.path contains "/nmap" or tgt.process.image.path contains "/telnet")))
```


# Original Sigma Rule:
```yaml
title: MacOS Network Service Scanning
id: 84bae5d4-b518-4ae0-b331-6d4afd34d00f
status: test
description: Detects enumeration of local or remote network services.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1046/T1046.md
author: Alejandro Ortuno, oscd.community
date: 2020-10-21
modified: 2021-11-27
tags:
    - attack.discovery
    - attack.t1046
logsource:
    category: process_creation
    product: macos
detection:
    selection_1:
        Image|endswith:
            - '/nc'
            - '/netcat'
    selection_2:
        Image|endswith:
            - '/nmap'
            - '/telnet'
    filter:
        CommandLine|contains: 'l'
    condition: (selection_1 and not filter) or selection_2
falsepositives:
    - Legitimate administration activities
level: low
```
