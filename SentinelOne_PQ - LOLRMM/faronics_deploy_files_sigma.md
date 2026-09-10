```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files (x86)\\Faronics\\Faronics Deploy Agent\\FaronicsDeployAgent.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Faronics\\Faronics Deploy Agent\\FWAService.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Faronics\\Faronics Deploy Agent\\FWA_UI_Agent.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Faronics\\Faronics Deploy Agent\\FRCServer.exe" or tgt.file.path contains "C:\\ProgramData\\Faronics\\StorageSpace\\FWA\\CloudAgentLogs.LOG" or tgt.file.path contains "C:\\ProgramData\\Faronics\\StorageSpace\\FWA\\Logs\\FWASvc.log"))
```


# Original Sigma Rule:
```yaml
title: Potential Faronics Deploy RMM Tool File Activity
id: 7664b62c-a556-5a1d-a8ea-405366836428
status: experimental
description: |
    Detects potential files activity of Faronics Deploy RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\Program Files (x86)\Faronics\Faronics Deploy Agent\FaronicsDeployAgent.exe'
            - 'C:\Program Files (x86)\Faronics\Faronics Deploy Agent\FWAService.exe'
            - 'C:\Program Files (x86)\Faronics\Faronics Deploy Agent\FWA_UI_Agent.exe'
            - 'C:\Program Files (x86)\Faronics\Faronics Deploy Agent\FRCServer.exe'
            - 'C:\ProgramData\Faronics\StorageSpace\FWA\CloudAgentLogs.LOG'
            - 'C:\ProgramData\Faronics\StorageSpace\FWA\Logs\FWASvc.log'
    condition: selection
falsepositives:
    - Legitimate use of Faronics Deploy
level: medium
```
