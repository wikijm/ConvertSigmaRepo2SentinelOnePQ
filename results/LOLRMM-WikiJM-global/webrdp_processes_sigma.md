```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "webrdp.exe")
```


# Original Sigma Rule:
```yaml
title: Potential WebRDP RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - webrdp.exe
  condition: selection
id: a873659f-031a-47ee-80ea-972bbcd23e36
status: experimental
description: Detects potential processes activity of WebRDP RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of WebRDP
level: medium
```
