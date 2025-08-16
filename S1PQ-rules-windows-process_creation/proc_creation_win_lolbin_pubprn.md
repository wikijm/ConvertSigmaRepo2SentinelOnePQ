```sql
// Translated content (automatically translated on 16-08-2025 02:03:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "\\pubprn.vbs" and tgt.process.cmdline contains "script:"))
```


# Original Sigma Rule:
```yaml
title: Pubprn.vbs Proxy Execution
id: 1fb76ab8-fa60-4b01-bddd-71e89bf555da
status: test
description: Detects the use of the 'Pubprn.vbs' Microsoft signed script to execute commands.
references:
    - https://lolbas-project.github.io/lolbas/Scripts/Pubprn/
author: frack113
date: 2022-05-28
tags:
    - attack.defense-evasion
    - attack.t1216.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\pubprn.vbs'
            - 'script:'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
