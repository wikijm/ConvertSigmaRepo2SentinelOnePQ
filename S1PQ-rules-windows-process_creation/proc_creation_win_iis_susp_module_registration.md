```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\w3wp.exe" and (tgt.process.cmdline contains "appcmd.exe add module" or (tgt.process.cmdline contains " system.enterpriseservices.internal.publish" and tgt.process.image.path contains "\powershell.exe") or (tgt.process.cmdline contains "gacutil" and tgt.process.cmdline contains " /I"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious IIS Module Registration
id: 043c4b8b-3a54-4780-9682-081cb6b8185c
status: test
description: Detects a suspicious IIS module registration as described in Microsoft threat report on IIS backdoors
references:
    - https://www.microsoft.com/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/
author: Florian Roth (Nextron Systems), Microsoft (idea)
date: 2022-08-04
modified: 2023-01-23
tags:
    - attack.persistence
    - attack.t1505.004
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\w3wp.exe'
    selection_cli_1:
        CommandLine|contains: 'appcmd.exe add module'
    selection_cli_2:
        CommandLine|contains: ' system.enterpriseservices.internal.publish'
        Image|endswith: '\powershell.exe'
    selection_cli_3:
        CommandLine|contains|all:
            - 'gacutil'
            - ' /I'
    condition: selection_parent and 1 of selection_cli_*
falsepositives:
    - Administrative activity
level: high
```
