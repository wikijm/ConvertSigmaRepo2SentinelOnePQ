```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "desktopnow.exe")
```


# Original Sigma Rule:
```yaml
title: Potential DesktopNow RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - desktopnow.exe
  condition: selection
id: 0e8c58da-b287-414c-86de-42efa6aaac8a
status: experimental
description: Detects potential processes activity of DesktopNow RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of DesktopNow
level: medium
```
