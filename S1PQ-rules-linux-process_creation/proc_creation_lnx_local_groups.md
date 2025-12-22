```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/groups" or ((tgt.process.image.path contains "/cat" or tgt.process.image.path contains "/ed" or tgt.process.image.path contains "/head" or tgt.process.image.path contains "/less" or tgt.process.image.path contains "/more" or tgt.process.image.path contains "/nano" or tgt.process.image.path contains "/tail" or tgt.process.image.path contains "/vi" or tgt.process.image.path contains "/vim") and tgt.process.cmdline contains "/etc/group")))
```


# Original Sigma Rule:
```yaml
title: Local Groups Discovery - Linux
id: 676381a6-15ca-4d73-a9c8-6a22e970b90d
status: test
description: Detects enumeration of local system groups. Adversaries may attempt to find local system groups and permission settings
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1069.001/T1069.001.md
author: Ömer Günal, Alejandro Ortuno, oscd.community
date: 2020-10-11
modified: 2025-06-04
tags:
    - attack.discovery
    - attack.t1069.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_1:
        Image|endswith: '/groups'
    selection_2:
        Image|endswith:
            - '/cat'
            - '/ed'
            - '/head'
            - '/less'
            - '/more'
            - '/nano'
            - '/tail'
            - '/vi'
            - '/vim'
        CommandLine|contains: '/etc/group'
    condition: 1 of selection_*
falsepositives:
    - Legitimate administration activities
level: low
```
