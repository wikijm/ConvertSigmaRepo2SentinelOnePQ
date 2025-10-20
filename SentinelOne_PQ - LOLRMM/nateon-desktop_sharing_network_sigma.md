```sql
// Translated content (automatically translated on 20-10-2025 00:53:47):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".nate.com" or event.dns.request contains ".nate.com"))
```


# Original Sigma Rule:
```yaml
title: Potential NateOn-desktop sharing RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.nate.com'
  condition: selection
id: a14b3a24-e9c8-4c9b-9668-65953bf06324
status: experimental
description: Detects potential network activity of NateOn-desktop sharing RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of NateOn-desktop sharing
level: medium
```
