```sql
// Translated content (automatically translated on 17-01-2026 01:43:17):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path="*pdq-connect*.exe")
```


# Original Sigma Rule:
```yaml
title: Potential PDQ Connect RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - pdq-connect*.exe
  condition: selection
id: 53f5bc8e-62d8-409e-9588-7910e706dc5f
status: experimental
description: Detects potential processes activity of PDQ Connect RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of PDQ Connect
level: medium
```
