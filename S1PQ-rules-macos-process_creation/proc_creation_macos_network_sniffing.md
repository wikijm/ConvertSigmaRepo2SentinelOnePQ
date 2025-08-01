```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/tcpdump" or tgt.process.image.path contains "/tshark"))
```


# Original Sigma Rule:
```yaml
title: Network Sniffing - MacOs
id: adc9bcc4-c39c-4f6b-a711-1884017bf043
status: test
description: |
  Detects the usage of tooling to sniff network traffic.
  An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1040/T1040.md
author: Alejandro Ortuno, oscd.community
date: 2020-10-14
modified: 2022-11-26
tags:
    - attack.discovery
    - attack.credential-access
    - attack.t1040
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith:
            - '/tcpdump'
            - '/tshark'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: informational
```
