```sql
// Translated content (automatically translated on 29-06-2025 00:59:53):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "ivanti.com/") or (event.dns.request contains "user_managed" or event.dns.request contains "ivanti.com/")))
```


# Original Sigma Rule:
```yaml
title: Potential RES Automation Manager RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - ivanti.com/
  condition: selection
id: c04bd4ba-7b7a-46a2-8eb0-0abf217e7122
status: experimental
description: Detects potential network activity of RES Automation Manager RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RES Automation Manager
level: medium
```
