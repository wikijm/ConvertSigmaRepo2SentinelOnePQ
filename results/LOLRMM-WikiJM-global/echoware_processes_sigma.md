```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path="*echoserver*.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Echoware RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - echoserver*.exe
  condition: selection
id: 6f03854f-166a-472e-a756-fecade3b89b9
status: experimental
description: Detects potential processes activity of Echoware RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Echoware
level: medium
```
