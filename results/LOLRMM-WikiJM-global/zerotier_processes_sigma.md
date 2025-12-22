```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*zerotier*.exe" or src.process.image.path contains "zero-powershell.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential ZeroTier RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - zerotier*.exe
    - zero-powershell.exe
  condition: selection
id: 3bb23fe4-d277-4cb0-ad3c-3ca22b56ba46
status: experimental
description: Detects potential processes activity of ZeroTier RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ZeroTier
level: medium
```
