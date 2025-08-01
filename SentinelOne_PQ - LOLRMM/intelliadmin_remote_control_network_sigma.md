```sql
// Translated content (automatically translated on 02-08-2025 00:55:07):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains ".intelliadmin.com" or url.address contains "intelliadmin.com/remote-control") or (event.dns.request contains "user_managed" or event.dns.request contains ".intelliadmin.com" or event.dns.request contains "intelliadmin.com/remote-control")))
```


# Original Sigma Rule:
```yaml
title: Potential IntelliAdmin Remote Control RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - '*.intelliadmin.com'
    - intelliadmin.com/remote-control
  condition: selection
id: 9bcee176-b4ba-4e1c-87fb-eb7f9dbfffae
status: experimental
description: Detects potential network activity of IntelliAdmin Remote Control RMM
  tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of IntelliAdmin Remote Control
level: medium
```
