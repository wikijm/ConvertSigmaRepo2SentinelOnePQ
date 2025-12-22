```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "C:\\Users\\USERNAME\\AppData\\Roaming\\Insync\\App\\Insync.exe" or src.process.image.path contains "Users\*\\AppData\\Roaming\\Insync\\App\\Insync.exe" or src.process.image.path contains "\\Insync.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Insync RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - C:\Users\USERNAME\AppData\Roaming\Insync\App\Insync.exe
    - '*Users\*\AppData\Roaming\Insync\App\Insync.exe'
    - '*\Insync.exe'
  condition: selection
id: 1b5f0d04-d37b-4e61-8d20-7dac0f2c3c7c
status: experimental
description: Detects potential processes activity of Insync RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Insync
level: medium
```
