```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/who" or tgt.process.image.path contains "/w" or tgt.process.image.path contains "/last" or tgt.process.image.path contains "/lsof" or tgt.process.image.path contains "/netstat") and (not (src.process.cmdline contains "/usr/bin/landscape-sysinfo" and tgt.process.image.path contains "/who"))))
```


# Original Sigma Rule:
```yaml
title: System Network Connections Discovery - Linux
id: 4c519226-f0cd-4471-bd2f-6fbb2bb68a79
status: test
description: Detects usage of system utilities to discover system network connections
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1049/T1049.md
author: Daniil Yugoslavskiy, oscd.community
date: 2020-10-19
modified: 2023-01-17
tags:
    - attack.discovery
    - attack.t1049
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/who'
            - '/w'
            - '/last'
            - '/lsof'
            - '/netstat'
    filter_landscape_sysinfo:
        ParentCommandLine|contains: '/usr/bin/landscape-sysinfo'
        Image|endswith: '/who'
    condition: selection and not 1 of filter_*
falsepositives:
    - Legitimate activities
level: low
```
