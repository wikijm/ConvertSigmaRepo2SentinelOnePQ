```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "komari-windows-386.exe" or src.process.image.path contains "komari-windows-amd64.exe" or src.process.image.path contains "komari-windows-arm64.exe" or src.process.image.path contains "komari-agent.exe") or (tgt.process.image.path contains "komari-windows-386.exe" or tgt.process.image.path contains "komari-windows-amd64.exe" or tgt.process.image.path contains "komari-windows-arm64.exe" or tgt.process.image.path contains "komari-agent.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Komari RMM Tool Process Activity
id: a38b9a4c-7c9f-54df-b8ae-0eb07ae23d26
status: experimental
description: |
    Detects potential processes activity of Komari RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - 'komari-windows-386.exe'
            - 'komari-windows-amd64.exe'
            - 'komari-windows-arm64.exe'
            - 'komari-agent.exe'
    selection_image:
        Image|endswith:
            - 'komari-windows-386.exe'
            - 'komari-windows-amd64.exe'
            - 'komari-windows-arm64.exe'
            - 'komari-agent.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Komari
level: medium
```
