```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "mRemoteNG.exe" or src.process.image.path contains "\mRemoteNG.exe" or src.process.image.path contains "\mRemoteNG.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential mRemoteNG RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - mRemoteNG.exe
    - '*\mRemoteNG.exe'
    - '*\mRemoteNG.exe'
  condition: selection
id: 0e45e59e-8578-4251-b097-15e6f99f5134
status: experimental
description: Detects potential processes activity of mRemoteNG RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of mRemoteNG
level: medium
```
