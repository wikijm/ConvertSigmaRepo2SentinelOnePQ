```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "set" and tgt.process.cmdline contains "&&" and tgt.process.cmdline contains "mshta" and tgt.process.cmdline contains "vbscript:createobject" and tgt.process.cmdline contains ".run" and tgt.process.cmdline contains "(window.close)"))
```


# Original Sigma Rule:
```yaml
title: Invoke-Obfuscation Via Use MSHTA
id: ac20ae82-8758-4f38-958e-b44a3140ca88
status: test
description: Detects Obfuscated Powershell via use MSHTA in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009   # (Task31)
author: Nikita Nazarov, oscd.community
date: 2020-10-08
modified: 2022-03-08
tags:
    - attack.defense-evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'set'
            - '&&'
            - 'mshta'
            - 'vbscript:createobject'
            - '.run'
            - '(window.close)'
    condition: selection
falsepositives:
    - Unknown
level: high
```
