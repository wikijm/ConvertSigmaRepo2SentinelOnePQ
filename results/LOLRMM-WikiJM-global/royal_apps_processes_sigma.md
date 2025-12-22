```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "royalserver.exe" or src.process.image.path contains "royalts.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Royal Apps RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - royalserver.exe
    - royalts.exe
  condition: selection
id: ab8415ac-55c4-483d-8843-96742a18aa14
status: experimental
description: Detects potential processes activity of Royal Apps RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Royal Apps
level: medium
```
