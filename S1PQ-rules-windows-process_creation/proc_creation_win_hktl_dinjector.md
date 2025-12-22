```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains " /am51" and tgt.process.cmdline contains " /password"))
```


# Original Sigma Rule:
```yaml
title: HackTool - DInjector PowerShell Cradle Execution
id: d78b5d61-187d-44b6-bf02-93486a80de5a
status: test
description: Detects the use of the Dinject PowerShell cradle based on the specific flags
references:
    - https://web.archive.org/web/20211001064856/https://github.com/snovvcrash/DInjector # Original got deleted. This is a fork
author: Florian Roth (Nextron Systems)
date: 2021-12-07
modified: 2023-02-04
tags:
    - attack.privilege-escalation
    - attack.defense-evasion
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - ' /am51'
            - ' /password'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```
