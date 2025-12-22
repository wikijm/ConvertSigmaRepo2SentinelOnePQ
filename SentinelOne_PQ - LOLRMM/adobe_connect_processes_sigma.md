```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path="*ConnectAppSetup*.exe" or src.process.image.path="*ConnectShellSetup*.exe" or src.process.image.path contains "Connect.exe" or src.process.image.path contains "ConnectDetector.exe") or (tgt.process.image.path="*ConnectAppSetup*.exe" or tgt.process.image.path="*ConnectShellSetup*.exe" or tgt.process.image.path contains "Connect.exe" or tgt.process.image.path contains "ConnectDetector.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Adobe Connect RMM Tool Process Activity
id: e8f2d33b-025e-47aa-be08-fe034fb8373f
status: experimental
description: |
    Detects potential processes activity of Adobe Connect RMM tool
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
            - ConnectAppSetup*.exe
            - ConnectShellSetup*.exe
            - Connect.exe
            - ConnectDetector.exe
    selection_image:
        Image|endswith:
            - ConnectAppSetup*.exe
            - ConnectShellSetup*.exe
            - Connect.exe
            - ConnectDetector.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Adobe Connect
level: medium
```
