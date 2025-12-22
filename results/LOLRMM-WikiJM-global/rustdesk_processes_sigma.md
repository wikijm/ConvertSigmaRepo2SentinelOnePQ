```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*rustdesk*.exe" or src.process.image.path contains "rustdesk.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential RustDesk RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - rustdesk*.exe
    - rustdesk.exe
  condition: selection
id: c586fb90-dabc-4b16-b0b3-f6b0f6024b91
status: experimental
description: Detects potential processes activity of RustDesk RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RustDesk
level: medium
```
