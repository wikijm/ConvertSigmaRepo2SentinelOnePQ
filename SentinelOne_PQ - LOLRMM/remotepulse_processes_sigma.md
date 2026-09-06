```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\InstallCore.exe" or tgt.process.image.path contains "\\InstallCore.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential RemotePulse RMM Tool Process Activity
id: d0c1d9e3-b7d9-5dbb-9342-e91fc2e80fa9
status: experimental
description: |
    Detects potential processes activity of RemotePulse RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-07-08
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith: '\\InstallCore.exe'
    selection_image:
        Image|endswith: '\\InstallCore.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of RemotePulse
level: medium
```
