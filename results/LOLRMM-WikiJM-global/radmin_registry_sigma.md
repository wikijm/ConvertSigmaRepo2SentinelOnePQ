```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
event.category="Registry" and (endpoint.os="windows" and registry.keyPath contains "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Radmin\v3.0\Server\Parameters\Radmin Security")
```


# Original Sigma Rule:
```yaml
title: Potential RAdmin RMM Tool Registry Activity
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains:
    - HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Radmin\v3.0\Server\Parameters\Radmin
      Security
  condition: selection
id: 239f1c2a-4f19-4c92-8ef5-5bbd9c367887
status: experimental
description: Detects potential registry activity of RAdmin RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RAdmin
level: medium
```
