```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".kace.com" or url.address contains "www.quest.com/kace/") or (event.dns.request contains ".kace.com" or event.dns.request contains "www.quest.com/kace/")))
```


# Original Sigma Rule:
```yaml
title: Potential Quest KACE Agent (formerly Dell KACE) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.kace.com'
    - www.quest.com/kace/
  condition: selection
id: 41765104-e0bb-4caf-9d80-f0b76da82722
status: experimental
description: Detects potential network activity of Quest KACE Agent (formerly Dell
  KACE) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Quest KACE Agent (formerly Dell KACE)
level: medium
```
