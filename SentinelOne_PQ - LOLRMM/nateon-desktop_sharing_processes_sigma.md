```sql
// Translated content (automatically translated on 09-10-2025 00:48:16):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*nateon*.exe" or src.process.image.path contains "nateon.exe" or src.process.image.path contains "nateonmain.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential NateOn-desktop sharing RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - nateon*.exe
    - nateon.exe
    - nateonmain.exe
  condition: selection
id: e2be2ea0-9906-4ce7-80a6-c803d38f04a6
status: experimental
description: Detects potential processes activity of NateOn-desktop sharing RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of NateOn-desktop sharing
level: medium
```
