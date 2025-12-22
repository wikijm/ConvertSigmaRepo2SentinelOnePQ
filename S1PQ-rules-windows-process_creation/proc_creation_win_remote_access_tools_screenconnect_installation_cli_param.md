```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "e=Access&" and tgt.process.cmdline contains "y=Guest&" and tgt.process.cmdline contains "&p=" and tgt.process.cmdline contains "&c=" and tgt.process.cmdline contains "&k="))
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - ScreenConnect Installation Execution
id: 75bfe6e6-cd8e-429e-91d3-03921e1d7962
status: test
description: Detects ScreenConnect program starts that establish a remote access to a system.
references:
    - https://www.anomali.com/blog/probable-iranian-cyber-actors-static-kitten-conducting-cyberespionage-campaign-targeting-uae-and-kuwait-government-agencies
author: Florian Roth (Nextron Systems)
date: 2021-02-11
modified: 2024-02-26
tags:
    - attack.persistence
    - attack.initial-access
    - attack.t1133
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'e=Access&'
            - 'y=Guest&'
            - '&p='
            - '&c='
            - '&k='
    condition: selection
falsepositives:
    - Legitimate use by administrative staff
level: medium
```
