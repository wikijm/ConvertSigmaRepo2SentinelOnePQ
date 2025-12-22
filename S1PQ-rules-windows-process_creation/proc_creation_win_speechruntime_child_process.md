```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\SpeechRuntime.exe")
```


# Original Sigma Rule:
```yaml
title: Suspicious Speech Runtime Binary Child Process
id: 78f10490-f2f4-4d19-a75b-4e0683bf3b8d
status: experimental
description: |
    Detects suspicious Speech Runtime Binary Execution by monitoring its child processes.
    Child processes spawned by SpeechRuntime.exe could indicate an attempt for lateral movement via COM & DCOM hijacking.
references:
    - https://github.com/rtecCyberSec/SpeechRuntimeMove
author: andrewdanis
date: 2025-10-23
logsource:
    category: process_creation
    product: windows
tags:
    - attack.defense-evasion
    - attack.lateral-movement
    - attack.t1021.003
    - attack.t1218
detection:
    selection:
        ParentImage|endswith: '\SpeechRuntime.exe'
    condition: selection
falsepositives:
    - Unlikely.
level: high
```
