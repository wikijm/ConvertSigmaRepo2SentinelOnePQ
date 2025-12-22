```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*ConnectAppSetup*.exe" or src.process.image.path="*ConnectShellSetup*.exe" or src.process.image.path contains "Connect.exe" or src.process.image.path contains "ConnectDetector.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Adobe Connect RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - ConnectAppSetup*.exe
    - ConnectShellSetup*.exe
    - Connect.exe
    - ConnectDetector.exe
  condition: selection
id: 4c9bea1b-36b4-40f8-b112-7a1db2dbf9ed
status: experimental
description: Detects potential processes activity of Adobe Connect RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Adobe Connect
level: medium
```
