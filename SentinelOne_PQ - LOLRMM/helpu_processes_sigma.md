```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "helpu_install.exe" or src.process.image.path contains "HelpuUpdater.exe" or src.process.image.path contains "HelpuManager.exe") or (tgt.process.image.path contains "helpu_install.exe" or tgt.process.image.path contains "HelpuUpdater.exe" or tgt.process.image.path contains "HelpuManager.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential HelpU RMM Tool Process Activity
id: b9d644d3-dc40-49ce-a18f-c54025834c5d
status: experimental
description: |
    Detects potential processes activity of HelpU RMM tool
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
            - helpu_install.exe
            - HelpuUpdater.exe
            - HelpuManager.exe
    selection_image:
        Image|endswith:
            - helpu_install.exe
            - HelpuUpdater.exe
            - HelpuManager.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of HelpU
level: medium
```
