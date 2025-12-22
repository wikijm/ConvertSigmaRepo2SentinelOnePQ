```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/who" or tgt.process.image.path contains "/w" or tgt.process.image.path contains "/last" or tgt.process.image.path contains "/lsof" or tgt.process.image.path contains "/netstat"))
```


# Original Sigma Rule:
```yaml
title: System Network Connections Discovery - MacOs
id: 9a7a0393-2144-4626-9bf1-7c2f5a7321db
status: test
description: Detects usage of system utilities to discover system network connections
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1049/T1049.md
author: Daniil Yugoslavskiy, oscd.community
date: 2020-10-19
modified: 2022-12-28
tags:
    - attack.discovery
    - attack.t1049
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith:
            - '/who'
            - '/w'
            - '/last'
            - '/lsof'
            - '/netstat'
    condition: selection
falsepositives:
    - Legitimate activities
level: informational
```
