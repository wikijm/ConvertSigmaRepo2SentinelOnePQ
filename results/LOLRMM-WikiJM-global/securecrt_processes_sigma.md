```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "C:\*\\SecureCRT.EXE" or src.process.image.path contains "\\SecureCRT.EXE"))
```


# Original Sigma Rule:
```yaml
title: Potential SecureCRT RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - C:\*\SecureCRT.EXE
    - '*\SecureCRT.EXE'
  condition: selection
id: 2061644f-6016-4f64-8c09-111c8e6422fe
status: experimental
description: Detects potential processes activity of SecureCRT RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of SecureCRT
level: medium
```
