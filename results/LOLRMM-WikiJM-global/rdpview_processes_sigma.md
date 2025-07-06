```sql
// Translated content (automatically translated on 06-07-2025 01:49:49):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "dwrcs.exe")
```


# Original Sigma Rule:
```yaml
title: Potential RDPView RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - dwrcs.exe
  condition: selection
id: 251045d0-56ca-4477-a089-7c7ccd0f7017
status: experimental
description: Detects potential processes activity of RDPView RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RDPView
level: medium
```
