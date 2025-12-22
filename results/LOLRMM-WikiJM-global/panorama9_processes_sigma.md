```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path="*p9agent*.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Panorama9 RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - p9agent*.exe
  condition: selection
id: 9913f423-61c0-41ca-a7e6-4853d5228b45
status: experimental
description: Detects potential processes activity of Panorama9 RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Panorama9
level: medium
```
