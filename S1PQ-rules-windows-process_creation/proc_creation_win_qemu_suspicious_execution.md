```sql
// Translated content (automatically translated on 04-05-2025 02:09:58):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.cmdline contains "-m 1M" or tgt.process.cmdline contains "-m 2M" or tgt.process.cmdline contains "-m 3M") and (tgt.process.cmdline contains "restrict=off" and tgt.process.cmdline contains "-netdev " and tgt.process.cmdline contains "connect=" and tgt.process.cmdline contains "-nographic")) and (not (tgt.process.cmdline contains " -cdrom " or tgt.process.cmdline contains " type=virt " or tgt.process.cmdline contains " -blockdev "))))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious Usage Of Qemu
id: 5fc297ae-25b6-488a-8f25-cc12ac29b744
status: test
description: |
    Detects potentially suspicious execution of the Qemu utility in a Windows environment.
    Threat actors have leveraged this utility and this technique for achieving network access as reported by Kaspersky.
references:
    - https://securelist.com/network-tunneling-with-qemu/111803/
    - https://www.qemu.org/docs/master/system/invocation.html#hxtool-5
author: Muhammad Faisal (@faisalusuf), Hunter Juhan (@threatHNTR)
date: 2024-06-03
tags:
    - attack.command-and-control
    - attack.t1090
    - attack.t1572
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '-m 1M' # VM with just 1MB of ram is insufficient this is a suspicious flag
            - '-m 2M'
            - '-m 3M'
        CommandLine|contains|all:
            - 'restrict=off'
            - '-netdev '
            - 'connect='
            - '-nographic' # This is also a key detection no one invoke without UI from console usually its a flag.
    filter_main_normal_usecase:
        CommandLine|contains:
            - ' -cdrom ' # Normal usage cases
            - ' type=virt '
            - ' -blockdev '
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
