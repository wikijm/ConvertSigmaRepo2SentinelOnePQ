```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*servereye*.exe" or src.process.image.path contains "ServiceProxyLocalSys.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential ServerEye RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - servereye*.exe
    - ServiceProxyLocalSys.exe
  condition: selection
id: a50f03f8-3431-42b6-96a0-ce50a88d4ef8
status: experimental
description: Detects potential processes activity of ServerEye RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ServerEye
level: medium
```
