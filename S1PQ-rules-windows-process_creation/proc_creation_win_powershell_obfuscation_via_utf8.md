```sql
// Translated content (automatically translated on 31-05-2025 02:01:25):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline contains "(WCHAR)0x")
```


# Original Sigma Rule:
```yaml
title: Potential PowerShell Obfuscation Via WCHAR
id: e312efd0-35a1-407f-8439-b8d434b438a6
status: test
description: Detects suspicious encoded character syntax often used for defense evasion
references:
    - https://twitter.com/0gtweet/status/1281103918693482496
author: Florian Roth (Nextron Systems)
date: 2020-07-09
modified: 2023-01-05
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense-evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '(WCHAR)0x'
    condition: selection
falsepositives:
    - Unknown
level: high
```
