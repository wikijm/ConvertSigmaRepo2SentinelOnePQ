```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "radmin.com" or event.dns.request contains "radmin.com"))
```


# Original Sigma Rule:
```yaml
title: Potential RAdmin RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - radmin.com
  condition: selection
id: 2f743e87-b02b-4178-b327-c0047197e2cd
status: experimental
description: Detects potential network activity of RAdmin RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RAdmin
level: medium
```
