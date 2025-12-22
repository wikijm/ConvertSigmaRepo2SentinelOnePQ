```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/firewall-cmd" or tgt.process.image.path contains "/ufw" or tgt.process.image.path contains "/iptables" or tgt.process.image.path contains "/netstat" or tgt.process.image.path contains "/ss" or tgt.process.image.path contains "/ip" or tgt.process.image.path contains "/ifconfig" or tgt.process.image.path contains "/systemd-resolve" or tgt.process.image.path contains "/route") or tgt.process.cmdline contains "/etc/resolv.conf"))
```


# Original Sigma Rule:
```yaml
title: System Network Discovery - Linux
id: e7bd1cfa-b446-4c88-8afb-403bcd79e3fa
status: test
description: Detects enumeration of local network configuration
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1016/T1016.md
author: Ömer Günal and remotephone, oscd.community
date: 2020-10-06
modified: 2022-09-15
tags:
    - attack.discovery
    - attack.t1016
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith:
            - '/firewall-cmd'
            - '/ufw'
            - '/iptables'
            - '/netstat'
            - '/ss'
            - '/ip'
            - '/ifconfig'
            - '/systemd-resolve'
            - '/route'
    selection_cli:
        CommandLine|contains: '/etc/resolv.conf'
    condition: 1 of selection_*
falsepositives:
    - Legitimate administration activities
level: informational
```
