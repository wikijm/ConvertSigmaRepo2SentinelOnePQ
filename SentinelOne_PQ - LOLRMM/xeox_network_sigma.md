```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".xeox.com" or url.address contains "xeox.com") or (event.dns.request contains ".xeox.com" or event.dns.request contains "xeox.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Xeox RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.xeox.com'
    - xeox.com
  condition: selection
id: 1ff42714-efb3-4550-81af-748ae2d1c526
status: experimental
description: Detects potential network activity of Xeox RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Xeox
level: medium
```
