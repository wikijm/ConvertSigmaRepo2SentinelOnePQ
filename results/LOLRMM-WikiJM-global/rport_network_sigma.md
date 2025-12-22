```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "rport.io") or (event.dns.request contains "user_managed" or event.dns.request contains "rport.io")))
```


# Original Sigma Rule:
```yaml
title: Potential RPort RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - rport.io
  condition: selection
id: 61cccc5f-5847-446b-a421-6a0ac02375ee
status: experimental
description: Detects potential network activity of RPort RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RPort
level: medium
```
