```sql
// Translated content (automatically translated on 25-08-2025 00:52:58):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\Syncthing.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Syncthing RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\Syncthing.exe'
  condition: selection
id: 44dd04d8-4691-4d7f-9fb0-c4eb4a654465
status: experimental
description: Detects potential processes activity of Syncthing RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Syncthing
level: medium
```
