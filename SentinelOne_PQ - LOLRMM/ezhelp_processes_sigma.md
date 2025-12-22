```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "ezhelpclientmanager.exe" or src.process.image.path contains "ezHelpManager.exe" or src.process.image.path contains "ezhelpclient.exe") or (tgt.process.image.path contains "ezhelpclientmanager.exe" or tgt.process.image.path contains "ezHelpManager.exe" or tgt.process.image.path contains "ezhelpclient.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential ezHelp RMM Tool Process Activity
id: 2c222c93-0da9-42b1-9e95-66f095c16abd
status: experimental
description: |
    Detects potential processes activity of ezHelp RMM tool
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
            - ezhelpclientmanager.exe
            - ezHelpManager.exe
            - ezhelpclient.exe
    selection_image:
        Image|endswith:
            - ezhelpclientmanager.exe
            - ezHelpManager.exe
            - ezhelpclient.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of ezHelp
level: medium
```
