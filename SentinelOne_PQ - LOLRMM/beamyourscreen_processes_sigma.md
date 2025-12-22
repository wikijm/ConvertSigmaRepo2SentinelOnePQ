```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "beamyourscreen.exe" or src.process.image.path contains "beamyourscreen-host.exe") or (tgt.process.image.path contains "beamyourscreen.exe" or tgt.process.image.path contains "beamyourscreen-host.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential BeamYourScreen RMM Tool Process Activity
id: c288ef87-eaa9-4de0-9ad5-39167ee79527
status: experimental
description: |
    Detects potential processes activity of BeamYourScreen RMM tool
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
            - beamyourscreen.exe
            - beamyourscreen-host.exe
    selection_image:
        Image|endswith:
            - beamyourscreen.exe
            - beamyourscreen-host.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of BeamYourScreen
level: medium
```
