```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "beamyourscreen.exe" or src.process.image.path contains "beamyourscreen-host.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential BeamYourScreen RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - beamyourscreen.exe
    - beamyourscreen-host.exe
  condition: selection
id: 90ef4fa3-63a2-49b6-a9df-3b6bc4d53114
status: experimental
description: Detects potential processes activity of BeamYourScreen RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of BeamYourScreen
level: medium
```
