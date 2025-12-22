```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/service" or tgt.process.image.path contains "/systemctl" or tgt.process.image.path contains "/chkconfig") and (tgt.process.cmdline contains "stop" or tgt.process.cmdline contains "disable")))
```


# Original Sigma Rule:
```yaml
title: Disable Or Stop Services
id: de25eeb8-3655-4643-ac3a-b662d3f26b6b
status: test
description: Detects the usage of utilities such as 'systemctl', 'service'...etc to stop or disable tools and services
references:
    - https://www.trendmicro.com/pl_pl/research/20/i/the-evolution-of-malicious-shell-scripts.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-15
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/service'
            - '/systemctl'
            - '/chkconfig'
        CommandLine|contains:
            - 'stop'
            - 'disable'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
```
