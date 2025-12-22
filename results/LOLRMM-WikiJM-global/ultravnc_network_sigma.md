```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "ultravnc.com" or url.address contains "user_managed") or (event.dns.request contains "ultravnc.com" or event.dns.request contains "user_managed")))
```


# Original Sigma Rule:
```yaml
title: Potential UltraVNC RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - ultravnc.com
    - user_managed
  condition: selection
id: 45678de7-dcbb-42b5-80d7-f21b399a1250
status: experimental
description: Detects potential network activity of UltraVNC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of UltraVNC
level: medium
```
