```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "NetLock_RMM_Agent_Installer.exe" or src.process.image.path contains "NetLock_RMM_User_Process.exe" or src.process.image.path contains "NetLock_RMM_User_UAC.exe") or (tgt.process.image.path contains "NetLock_RMM_Agent_Installer.exe" or tgt.process.image.path contains "NetLock_RMM_User_Process.exe" or tgt.process.image.path contains "NetLock_RMM_User_UAC.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential NetLock RMM RMM Tool Process Activity
id: 983bff01-624c-43c9-929f-e04756a7ac52
status: experimental
description: |
    Detects potential processes activity of NetLock RMM RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - NetLock_RMM_Agent_Installer.exe
            - NetLock_RMM_User_Process.exe
            - NetLock_RMM_User_UAC.exe
    selection_image:
        Image|endswith:
            - NetLock_RMM_Agent_Installer.exe
            - NetLock_RMM_User_Process.exe
            - NetLock_RMM_User_UAC.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of NetLock RMM
level: medium
```
