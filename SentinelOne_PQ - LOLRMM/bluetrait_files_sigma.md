```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files (x86)\\Bluetrait Agent\\Bluetrait MSP Agent.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Bluetrait Agent\\BluetraitUserAgent.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Bluetrait Agent\\config.db" or tgt.file.path contains "C:\\Program Files (x86)\\Bluetrait Agent\\config.json" or tgt.file.path contains "C:\\Program Files (x86)\\Bluetrait Agent\\libraries\\paexec.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Bluetrait RMM Tool File Activity
id: 28f4af4e-d03d-4148-98fe-8ccea55e4572
status: experimental
description: |
    Detects potential files activity of Bluetrait RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - C:\Program Files (x86)\Bluetrait Agent\Bluetrait MSP Agent.exe
            - C:\Program Files (x86)\Bluetrait Agent\BluetraitUserAgent.exe
            - C:\Program Files (x86)\Bluetrait Agent\config.db
            - C:\Program Files (x86)\Bluetrait Agent\config.json
            - C:\Program Files (x86)\Bluetrait Agent\libraries\paexec.exe
    condition: selection
falsepositives:
    - Legitimate use of Bluetrait
level: medium
```
