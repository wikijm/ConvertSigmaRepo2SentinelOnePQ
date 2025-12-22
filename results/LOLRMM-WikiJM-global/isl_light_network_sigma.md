```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "islonline.com" or event.dns.request contains "islonline.com"))
```


# Original Sigma Rule:
```yaml
title: Potential ISL Light RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - islonline.com
  condition: selection
id: 962c66b5-e5d4-4e59-b31e-d127fbc500bb
status: experimental
description: Detects potential network activity of ISL Light RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ISL Light
level: medium
```
