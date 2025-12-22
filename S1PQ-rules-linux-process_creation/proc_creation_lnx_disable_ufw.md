```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.cmdline contains "-ufw-init" and tgt.process.cmdline contains "force-stop") or (tgt.process.cmdline contains "ufw" and tgt.process.cmdline contains "disable")))
```


# Original Sigma Rule:
```yaml
title: Ufw Force Stop Using Ufw-Init
id: 84c9e83c-599a-458a-a0cb-0ecce44e807a
status: test
description: Detects attempts to force stop the ufw using ufw-init
references:
    - https://blogs.blackberry.com/
    - https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-01-18
tags:
    - attack.defense-evasion
    - attack.t1562.004
logsource:
    product: linux
    category: process_creation
detection:
    selection_init:
        CommandLine|contains|all:
            - '-ufw-init'
            - 'force-stop'
    selection_ufw:
        CommandLine|contains|all:
            - 'ufw'
            - 'disable'
    condition: 1 of selection_*
falsepositives:
    - Network administrators
level: medium
```
