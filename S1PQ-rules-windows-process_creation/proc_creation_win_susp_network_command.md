```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "ipconfig /all" or tgt.process.cmdline contains "netsh interface show interface" or tgt.process.cmdline contains "arp -a" or tgt.process.cmdline contains "nbtstat -n" or tgt.process.cmdline contains "net config" or tgt.process.cmdline contains "route print"))
```


# Original Sigma Rule:
```yaml
title: Suspicious Network Command
id: a29c1813-ab1f-4dde-b489-330b952e91ae
status: test
description: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1016/T1016.md#atomic-test-1---system-network-configuration-discovery-on-windows
author: frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
date: 2021-12-07
modified: 2022-04-11
tags:
    - attack.discovery
    - attack.t1016
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'ipconfig /all'
            - 'netsh interface show interface'
            - 'arp -a'
            - 'nbtstat -n'
            - 'net config'
            - 'route print'
    condition: selection
falsepositives:
    - Administrator, hotline ask to user
level: low
```
