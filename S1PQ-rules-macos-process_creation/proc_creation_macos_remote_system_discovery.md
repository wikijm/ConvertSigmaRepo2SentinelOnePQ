```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and ((tgt.process.image.path contains "/arp" and tgt.process.cmdline contains "-a") or (tgt.process.image.path contains "/ping" and (tgt.process.cmdline contains " 10." or tgt.process.cmdline contains " 192.168." or tgt.process.cmdline contains " 172.16." or tgt.process.cmdline contains " 172.17." or tgt.process.cmdline contains " 172.18." or tgt.process.cmdline contains " 172.19." or tgt.process.cmdline contains " 172.20." or tgt.process.cmdline contains " 172.21." or tgt.process.cmdline contains " 172.22." or tgt.process.cmdline contains " 172.23." or tgt.process.cmdline contains " 172.24." or tgt.process.cmdline contains " 172.25." or tgt.process.cmdline contains " 172.26." or tgt.process.cmdline contains " 172.27." or tgt.process.cmdline contains " 172.28." or tgt.process.cmdline contains " 172.29." or tgt.process.cmdline contains " 172.30." or tgt.process.cmdline contains " 172.31." or tgt.process.cmdline contains " 127." or tgt.process.cmdline contains " 169.254."))))
```


# Original Sigma Rule:
```yaml
title: Macos Remote System Discovery
id: 10227522-8429-47e6-a301-f2b2d014e7ad
status: test
description: Detects the enumeration of other remote systems.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md
author: Alejandro Ortuno, oscd.community
date: 2020-10-22
modified: 2021-11-27
tags:
    - attack.discovery
    - attack.t1018
logsource:
    category: process_creation
    product: macos
detection:
    selection_1:
        Image|endswith: '/arp'
        CommandLine|contains: '-a'
    selection_2:
        Image|endswith: '/ping'
        CommandLine|contains:
            - ' 10.' # 10.0.0.0/8
            - ' 192.168.' # 192.168.0.0/16
            - ' 172.16.' # 172.16.0.0/12
            - ' 172.17.'
            - ' 172.18.'
            - ' 172.19.'
            - ' 172.20.'
            - ' 172.21.'
            - ' 172.22.'
            - ' 172.23.'
            - ' 172.24.'
            - ' 172.25.'
            - ' 172.26.'
            - ' 172.27.'
            - ' 172.28.'
            - ' 172.29.'
            - ' 172.30.'
            - ' 172.31.'
            - ' 127.' # 127.0.0.0/8
            - ' 169.254.' # 169.254.0.0/16
    condition: 1 of selection*
falsepositives:
    - Legitimate administration activities
level: informational
```
