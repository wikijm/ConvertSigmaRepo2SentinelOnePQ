```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "naverisk.com") or (event.dns.request contains "user_managed" or event.dns.request contains "naverisk.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Naverisk RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - naverisk.com
  condition: selection
id: 5dbbce46-68fb-4d3c-a3e0-6c0d9e23cde9
status: experimental
description: Detects potential network activity of Naverisk RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Naverisk
level: medium
```
