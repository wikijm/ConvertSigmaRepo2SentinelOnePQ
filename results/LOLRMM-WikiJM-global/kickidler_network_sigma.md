```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "kickidler.com" or url.address contains "my.kickidler.com") or (event.dns.request contains "kickidler.com" or event.dns.request contains "my.kickidler.com")))
```


# Original Sigma Rule:
```yaml
title: Potential KickIdler RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - kickidler.com
    - my.kickidler.com
  condition: selection
id: c20767f9-ddf7-44af-84dc-1c2731c69665
status: experimental
description: Detects potential network activity of KickIdler RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of KickIdler
level: medium
```
