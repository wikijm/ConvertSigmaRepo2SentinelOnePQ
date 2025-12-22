```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/sudo" and (tgt.process.cmdline contains " tc " and tgt.process.cmdline contains " enp0s3 ") and (tgt.process.cmdline contains " qdisc " or tgt.process.cmdline contains " filter ")))
```


# Original Sigma Rule:
```yaml
title: Triple Cross eBPF Rootkit Install Commands
id: 22236d75-d5a0-4287-bf06-c93b1770860f
status: test
description: Detects default install commands of the Triple Cross eBPF rootkit based on the "deployer.sh" script
references:
    - https://github.com/h3xduck/TripleCross/blob/1f1c3e0958af8ad9f6ebe10ab442e75de33e91de/apps/deployer.sh
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-05
tags:
    - attack.defense-evasion
    - attack.t1014
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/sudo'
        CommandLine|contains|all:
            - ' tc '
            - ' enp0s3 '
        CommandLine|contains:
            - ' qdisc '
            - ' filter '
    condition: selection
falsepositives:
    - Unlikely
level: high
```
