```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\register-cimprovider.exe" and (tgt.process.cmdline contains "-path" and tgt.process.cmdline contains "dll")))
```


# Original Sigma Rule:
```yaml
title: DLL Execution Via Register-cimprovider.exe
id: a2910908-e86f-4687-aeba-76a5f996e652
status: test
description: Detects using register-cimprovider.exe to execute arbitrary dll file.
references:
    - https://twitter.com/PhilipTsukerman/status/992021361106268161
    - https://lolbas-project.github.io/lolbas/Binaries/Register-cimprovider/
author: Ivan Dyachkov, Yulia Fomina, oscd.community
date: 2020-10-07
modified: 2021-11-27
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.defense-evasion
    - attack.t1574
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\register-cimprovider.exe'
        CommandLine|contains|all:
            - '-path'
            - 'dll'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
