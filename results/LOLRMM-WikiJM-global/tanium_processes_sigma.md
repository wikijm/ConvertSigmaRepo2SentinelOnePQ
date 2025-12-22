```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "TaniumClient.exe" or src.process.image.path contains "TaniumCX.exe" or src.process.image.path contains "TaniumExecWrapper.exe" or src.process.image.path contains "TaniumFileInfo.exe" or src.process.image.path contains "TPowerShell.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Tanium RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - TaniumClient.exe
    - TaniumCX.exe
    - TaniumExecWrapper.exe
    - TaniumFileInfo.exe
    - TPowerShell.exe
  condition: selection
id: aeb6d6fa-ca62-4f34-91c6-5a5dbf4d2448
status: experimental
description: Detects potential processes activity of Tanium RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Tanium
level: medium
```
