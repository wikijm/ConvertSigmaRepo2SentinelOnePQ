```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\Livedrive-Setup.exe")
```


# Original Sigma Rule:
```yaml
title: Potential TeraCLOUD RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\Livedrive-Setup.exe'
  condition: selection
id: 77ad4b3c-dc22-42b6-931d-8bbc1a648ead
status: experimental
description: Detects potential processes activity of TeraCLOUD RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of TeraCLOUD
level: medium
```
