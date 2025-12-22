```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\Cyberduck.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Cyberduck RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\Cyberduck.exe'
  condition: selection
id: e55934bd-a4a0-4c44-8be7-cb86fb42f5d2
status: experimental
description: Detects potential processes activity of Cyberduck RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Cyberduck
level: medium
```
