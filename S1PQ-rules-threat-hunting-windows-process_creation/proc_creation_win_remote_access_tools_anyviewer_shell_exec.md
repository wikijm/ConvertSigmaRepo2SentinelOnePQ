```sql
// Translated content (automatically translated on 22-12-2025 00:55:34):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\AVCore.exe" and src.process.cmdline contains "AVCore.exe\" -d" and tgt.process.image.path contains "\\cmd.exe"))
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - Cmd.EXE Execution via AnyViewer
id: bc533330-fc29-44c0-b245-7dc6e5939c87
status: test
description: |
    Detects execution of "cmd.exe" via the AnyViewer RMM agent on a remote management sessions.
references:
    - https://www.anyviewer.com/help/remote-technical-support.html
author: '@kostastsale'
date: 2024-08-03
tags:
    - attack.execution
    - attack.persistence
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\AVCore.exe'
        ParentCommandLine|contains: 'AVCore.exe" -d'
        Image|endswith: '\cmd.exe'
    condition: selection
falsepositives:
    - Legitimate use for admin activity.
level: medium
```
