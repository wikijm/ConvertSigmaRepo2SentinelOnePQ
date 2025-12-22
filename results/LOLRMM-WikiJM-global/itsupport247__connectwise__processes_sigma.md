```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "saazapsc.exe")
```


# Original Sigma Rule:
```yaml
title: Potential ITSupport247 (ConnectWise) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - saazapsc.exe
  condition: selection
id: 68ba025f-ec04-406d-98ab-4f6517a09105
status: experimental
description: Detects potential processes activity of ITSupport247 (ConnectWise) RMM
  tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ITSupport247 (ConnectWise)
level: medium
```
