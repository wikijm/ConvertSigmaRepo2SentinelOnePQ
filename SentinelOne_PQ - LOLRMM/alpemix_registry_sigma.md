```sql
// Translated content (automatically translated on 02-08-2025 00:55:07):
event.category="Registry" and (endpoint.os="windows" and registry.keyPath contains "HKLM\SYSTEM\CurrentControlSet\Services\AlpemixSrvcx")
```


# Original Sigma Rule:
```yaml
title: Potential Alpemix RMM Tool Registry Activity
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains:
    - HKLM\SYSTEM\CurrentControlSet\Services\AlpemixSrvcx
  condition: selection
id: 69e8d2cb-44e6-478e-9fc5-73daa1bb78c2
status: experimental
description: Detects potential registry activity of Alpemix RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Alpemix
level: medium
```
