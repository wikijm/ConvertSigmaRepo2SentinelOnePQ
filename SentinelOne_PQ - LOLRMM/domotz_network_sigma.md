```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".domotz.co" or url.address contains "domotz.com" or url.address contains "cell-1.domotz.com") or (event.dns.request contains ".domotz.co" or event.dns.request contains "domotz.com" or event.dns.request contains "cell-1.domotz.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Domotz RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.domotz.co'
    - domotz.com
    - '*cell-1.domotz.com'
  condition: selection
id: 3e2c6509-b097-4847-9162-be651728e793
status: experimental
description: Detects potential network activity of Domotz RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Domotz
level: medium
```
