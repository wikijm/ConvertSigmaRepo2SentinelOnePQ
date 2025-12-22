```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "sysdiag.exe")
```


# Original Sigma Rule:
```yaml
title: Potential SpyAnywhere RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - sysdiag.exe
  condition: selection
id: cd302294-1c3e-479a-a464-aff706a761af
status: experimental
description: Detects potential processes activity of SpyAnywhere RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of SpyAnywhere
level: medium
```
