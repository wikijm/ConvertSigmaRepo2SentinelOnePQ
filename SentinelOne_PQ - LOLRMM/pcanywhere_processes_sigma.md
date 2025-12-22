```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "awhost32.exe" or src.process.image.path contains "awrem32.exe" or src.process.image.path contains "pcaquickconnect.exe" or src.process.image.path contains "winaw32.exe") or (tgt.process.image.path contains "awhost32.exe" or tgt.process.image.path contains "awrem32.exe" or tgt.process.image.path contains "pcaquickconnect.exe" or tgt.process.image.path contains "winaw32.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential pcAnywhere RMM Tool Process Activity
id: ab6317ad-0d76-4778-9e9b-1dc463be1307
status: experimental
description: |
    Detects potential processes activity of pcAnywhere RMM tool
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
            - awhost32.exe
            - awrem32.exe
            - pcaquickconnect.exe
            - winaw32.exe
    selection_image:
        Image|endswith:
            - awhost32.exe
            - awrem32.exe
            - pcaquickconnect.exe
            - winaw32.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of pcAnywhere
level: medium
```
