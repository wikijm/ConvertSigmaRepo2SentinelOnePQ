```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "royalapps.com" or event.dns.request contains "royalapps.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Royal TS RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - royalapps.com
  condition: selection
id: 6b0eb373-eb26-4648-84e3-cfd0259bbd8e
status: experimental
description: Detects potential network activity of Royal TS RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Royal TS
level: medium
```
