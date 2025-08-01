```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\tshark.exe" and tgt.process.cmdline contains "-i") or tgt.process.image.path contains "\windump.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Network Sniffing Activity Using Network Tools
id: ba1f7802-adc7-48b4-9ecb-81e227fddfd5
status: test
description: |
    Detects potential network sniffing via use of network tools such as "tshark", "windump".
    Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection.
    An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1040/T1040.md
author: Timur Zinniatullin, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: 2019-10-21
modified: 2023-02-20
tags:
    - attack.credential-access
    - attack.discovery
    - attack.t1040
logsource:
    category: process_creation
    product: windows
detection:
    selection_tshark:
        Image|endswith: '\tshark.exe'
        CommandLine|contains: '-i'
    selection_windump:
        Image|endswith: '\windump.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate administration activity to troubleshoot network issues
level: medium
```
