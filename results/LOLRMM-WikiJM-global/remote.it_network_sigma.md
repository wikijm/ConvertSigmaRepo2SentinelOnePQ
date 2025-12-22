```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "auth.api.remote.it" or url.address contains "api.remote.it" or url.address contains "remote.it") or (event.dns.request contains "auth.api.remote.it" or event.dns.request contains "api.remote.it" or event.dns.request contains "remote.it")))
```


# Original Sigma Rule:
```yaml
title: Potential Remote.it RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - auth.api.remote.it
    - api.remote.it
    - remote.it
  condition: selection
id: 99b84fe2-27e5-4fc8-8da7-b11ee8e9dc36
status: experimental
description: Detects potential network activity of Remote.it RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Remote.it
level: medium
```
