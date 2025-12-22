```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "iadmin.exe" or src.process.image.path contains "intelliadmin.exe" or src.process.image.path contains "agent32.exe" or src.process.image.path contains "agent64.exe" or src.process.image.path contains "agent_setup_5.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential IntelliAdmin Remote Control RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - iadmin.exe
    - intelliadmin.exe
    - agent32.exe
    - agent64.exe
    - agent_setup_5.exe
  condition: selection
id: 92dd3c65-418e-4acf-802e-d1e2bf377863
status: experimental
description: Detects potential processes activity of IntelliAdmin Remote Control RMM
  tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of IntelliAdmin Remote Control
level: medium
```
