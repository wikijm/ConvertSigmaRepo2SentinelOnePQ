```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and ((tgt.process.image.path contains "/dscl" and (tgt.process.cmdline contains "list" and tgt.process.cmdline contains "/users")) or (tgt.process.image.path contains "/dscacheutil" and (tgt.process.cmdline contains "-q" and tgt.process.cmdline contains "user")) or tgt.process.cmdline contains "'x:0:'" or (tgt.process.image.path contains "/cat" and (tgt.process.cmdline contains "/etc/passwd" or tgt.process.cmdline contains "/etc/sudoers")) or tgt.process.image.path contains "/id" or (tgt.process.image.path contains "/lsof" and tgt.process.cmdline contains "-u")))
```


# Original Sigma Rule:
```yaml
title: Local System Accounts Discovery - MacOs
id: ddf36b67-e872-4507-ab2e-46bda21b842c
status: test
description: Detects enumeration of local systeam accounts on MacOS
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1087.001/T1087.001.md
author: Alejandro Ortuno, oscd.community
date: 2020-10-08
modified: 2022-11-27
tags:
    - attack.discovery
    - attack.t1087.001
logsource:
    category: process_creation
    product: macos
detection:
    selection_1:
        Image|endswith: '/dscl'
        CommandLine|contains|all:
            - 'list'
            - '/users'
    selection_2:
        Image|endswith: '/dscacheutil'
        CommandLine|contains|all:
            - '-q'
            - 'user'
    selection_3:
        CommandLine|contains: '''x:0:'''
    selection_4:
        Image|endswith: '/cat'
        CommandLine|contains:
            - '/etc/passwd'
            - '/etc/sudoers'
    selection_5:
        Image|endswith: '/id'
    selection_6:
        Image|endswith: '/lsof'
        CommandLine|contains: '-u'
    condition: 1 of selection*
falsepositives:
    - Legitimate administration activities
level: low
```
