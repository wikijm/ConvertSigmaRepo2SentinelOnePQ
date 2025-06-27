```sql
// Translated content (automatically translated on 27-06-2025 00:54:12):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path="*remcos*.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Remcos RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - remcos*.exe
  condition: selection
id: 18b30604-7121-43a5-9015-dcf63d2e6d0b
status: experimental
description: Detects potential processes activity of Remcos RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Remcos
level: medium
```
