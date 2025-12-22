```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "UtilityFunctions.ps1" or tgt.process.cmdline contains "RegSnapin "))
```


# Original Sigma Rule:
```yaml
title: UtilityFunctions.ps1 Proxy Dll
id: 0403d67d-6227-4ea8-8145-4e72db7da120
status: test
description: Detects the use of a Microsoft signed script executing a managed DLL with PowerShell.
references:
    - https://lolbas-project.github.io/lolbas/Scripts/UtilityFunctions/
author: frack113
date: 2022-05-28
tags:
    - attack.defense-evasion
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'UtilityFunctions.ps1'
            - 'RegSnapin '
    condition: selection
falsepositives:
    - Unknown
level: medium
```
