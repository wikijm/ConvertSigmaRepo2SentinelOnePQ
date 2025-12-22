```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "level.io" or url.address contains ".level.io") or (event.dns.request contains "level.io" or event.dns.request contains ".level.io")))
```


# Original Sigma Rule:
```yaml
title: Potential Level.io RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - level.io
    - '*.level.io'
  condition: selection
id: 5b3131cc-ad91-4dbf-b429-2b013e7f8a69
status: experimental
description: Detects potential network activity of Level.io RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Level.io
level: medium
```
