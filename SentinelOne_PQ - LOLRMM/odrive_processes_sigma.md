```sql
// Translated content (automatically translated on 02-08-2025 00:55:07):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\Odriveapp.exe")
```


# Original Sigma Rule:
```yaml
title: Potential ODrive RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\Odriveapp.exe'
  condition: selection
id: 3ecd5480-76d3-45f4-9c12-0adb425592a5
status: experimental
description: Detects potential processes activity of ODrive RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ODrive
level: medium
```
