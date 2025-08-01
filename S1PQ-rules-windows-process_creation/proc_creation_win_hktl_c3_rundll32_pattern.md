```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "rundll32.exe" and tgt.process.cmdline contains ".dll" and tgt.process.cmdline contains "StartNodeRelay"))
```


# Original Sigma Rule:
```yaml
title: HackTool - F-Secure C3 Load by Rundll32
id: b18c9d4c-fac9-4708-bd06-dd5bfacf200f
status: test
description: F-Secure C3 produces DLLs with a default exported StartNodeRelay function.
references:
    - https://github.com/FSecureLABS/C3/blob/11a081fd3be2aaf2a879f6b6e9a96ecdd24966ef/Src/NodeRelayDll/NodeRelayDll.cpp#L12
author: Alfie Champion (ajpc500)
date: 2021-06-02
modified: 2023-03-05
tags:
    - attack.defense-evasion
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'rundll32.exe'
            - '.dll'
            - 'StartNodeRelay'
    condition: selection
falsepositives:
    - Unknown
level: critical
```
