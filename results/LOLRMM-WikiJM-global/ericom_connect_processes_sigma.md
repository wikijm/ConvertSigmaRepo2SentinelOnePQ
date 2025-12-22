```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*EricomConnectRemoteHost*.exe" or src.process.image.path contains "ericomconnnectconfigurationtool.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Ericom Connect RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - EricomConnectRemoteHost*.exe
    - ericomconnnectconfigurationtool.exe
  condition: selection
id: 9e1e58c9-17fe-4239-9292-9e5466ff5471
status: experimental
description: Detects potential processes activity of Ericom Connect RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Ericom Connect
level: medium
```
