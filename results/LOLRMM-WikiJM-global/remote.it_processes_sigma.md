```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "remote-it-installer.exe" or src.process.image.path contains "remote.it.exe" or src.process.image.path contains "remoteit.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Remote.it RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - remote-it-installer.exe
    - remote.it.exe
    - remoteit.exe
  condition: selection
id: 38279ba5-0030-43ca-a724-b631f7080888
status: experimental
description: Detects potential processes activity of Remote.it RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Remote.it
level: medium
```
