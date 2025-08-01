```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains ":\Windows\Sysnative\" or tgt.process.image.path contains ":\Windows\Sysnative\"))
```


# Original Sigma Rule:
```yaml
title: Process Creation Using Sysnative Folder
id: 3c1b5fb0-c72f-45ba-abd1-4d4c353144ab
status: test
description: Detects process creation events that use the Sysnative folder (common for CobaltStrike spawns)
references:
    - https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/
author: Max Altgelt (Nextron Systems)
date: 2022-08-23
modified: 2023-12-14
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    sysnative:
        - CommandLine|contains: ':\Windows\Sysnative\'
        - Image|contains: ':\Windows\Sysnative\'
    condition: sysnative
falsepositives:
    - Unknown
level: medium
```
