```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "deskday.ai" or url.address contains "app.deskday.ai") or (event.dns.request contains "deskday.ai" or event.dns.request contains "app.deskday.ai")))
```


# Original Sigma Rule:
```yaml
title: Potential DeskDay RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - deskday.ai
    - app.deskday.ai
  condition: selection
id: 38872e2b-956b-40eb-9af0-09f9bc4258ca
status: experimental
description: Detects potential network activity of DeskDay RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of DeskDay
level: medium
```
