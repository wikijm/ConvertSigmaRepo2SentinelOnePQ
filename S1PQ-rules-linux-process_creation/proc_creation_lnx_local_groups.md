```sql
// Translated content (automatically translated on 04-06-2025 00:57:09):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/groups" or ((tgt.process.image.path contains "/cat" or tgt.process.image.path contains "/head" or tgt.process.image.path contains "/tail" or tgt.process.image.path contains "/more") and tgt.process.cmdline contains "/etc/group")))
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
modified: 2022-11-27
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
            - '/head'
            - '/tail'
            - '/more'
        CommandLine|contains: '/etc/group'
    condition: 1 of selection*
falsepositives:
    - Legitimate administration activities
level: low
```
