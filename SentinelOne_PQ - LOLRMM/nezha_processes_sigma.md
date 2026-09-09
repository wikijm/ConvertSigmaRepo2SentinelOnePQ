```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\nezha-agent.exe" or src.process.image.path contains "\\dashboard-windows-amd64.exe") or (tgt.process.image.path contains "\\nezha-agent.exe" or tgt.process.image.path contains "\\dashboard-windows-amd64.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Nezha RMM Tool Process Activity
id: 5f2bf4b1-c382-55fd-9ce6-dd91a480fd03
status: experimental
description: |
    Detects potential processes activity of Nezha RMM tool
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
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\nezha-agent.exe'
            - '\\dashboard-windows-amd64.exe'
    selection_image:
        Image|endswith:
            - '\\nezha-agent.exe'
            - '\\dashboard-windows-amd64.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Nezha
level: medium
```
