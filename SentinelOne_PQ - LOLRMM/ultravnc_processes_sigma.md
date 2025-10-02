```sql
// Translated content (automatically translated on 02-10-2025 00:46:36):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path="*UltraVNC*.exe")
```


# Original Sigma Rule:
```yaml
title: Potential UltraVNC RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - UltraVNC*.exe
  condition: selection
id: c956baf8-4414-4b19-97cc-edfe477cec0f
status: experimental
description: Detects potential processes activity of UltraVNC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of UltraVNC
level: medium
```
