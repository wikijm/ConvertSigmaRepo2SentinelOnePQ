```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "hsloader.exe" or src.process.image.path contains "InstantHousecall.exe" or src.process.image.path contains "ihcserver.exe" or src.process.image.path contains "instanthousecall.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Instant Housecall RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - hsloader.exe
    - InstantHousecall.exe
    - ihcserver.exe
    - instanthousecall.exe
  condition: selection
id: ff766798-323b-4075-a0cb-67b617ede5a9
status: experimental
description: Detects potential processes activity of Instant Housecall RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Instant Housecall
level: medium
```
