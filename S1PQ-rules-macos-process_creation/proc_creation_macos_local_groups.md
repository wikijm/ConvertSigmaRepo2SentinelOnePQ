```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and ((tgt.process.image.path contains "/dscacheutil" and (tgt.process.cmdline contains "-q" and tgt.process.cmdline contains "group")) or (tgt.process.image.path contains "/cat" and tgt.process.cmdline contains "/etc/group") or (tgt.process.image.path contains "/dscl" and (tgt.process.cmdline contains "-list" and tgt.process.cmdline contains "/groups"))))
```


# Original Sigma Rule:
```yaml
title: Local Groups Discovery - MacOs
id: 89bb1f97-c7b9-40e8-b52b-7d6afbd67276
status: test
description: Detects enumeration of local system groups
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
    product: macos
detection:
    selection_1:
        Image|endswith: '/dscacheutil'
        CommandLine|contains|all:
            - '-q'
            - 'group'
    selection_2:
        Image|endswith: '/cat'
        CommandLine|contains: '/etc/group'
    selection_3:
        Image|endswith: '/dscl'
        CommandLine|contains|all:
            - '-list'
            - '/groups'
    condition: 1 of selection*
falsepositives:
    - Legitimate administration activities
level: informational
```
