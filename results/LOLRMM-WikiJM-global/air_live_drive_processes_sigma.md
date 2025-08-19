```sql
// Translated content (automatically translated on 19-08-2025 01:38:06):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\AirLiveDrive.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Air Live Drive RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\AirLiveDrive.exe'
  condition: selection
id: a77cc3b0-d89a-4f23-aea9-e960e3f56515
status: experimental
description: Detects potential processes activity of Air Live Drive RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Air Live Drive
level: medium
```
