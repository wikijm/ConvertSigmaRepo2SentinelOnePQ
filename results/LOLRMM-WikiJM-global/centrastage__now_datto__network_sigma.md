```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".rmm.datto.com" or url.address contains "cc.centrastage.net" or url.address contains "datto.com/au/products/rmm/") or (event.dns.request contains ".rmm.datto.com" or event.dns.request contains "cc.centrastage.net" or event.dns.request contains "datto.com/au/products/rmm/")))
```


# Original Sigma Rule:
```yaml
title: Potential CentraStage (Now Datto) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.rmm.datto.com'
    - '*cc.centrastage.net'
    - datto.com/au/products/rmm/
  condition: selection
id: 3a88e2fc-5a18-462a-ae8d-4b397d11db5d
status: experimental
description: Detects potential network activity of CentraStage (Now Datto) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of CentraStage (Now Datto)
level: medium
```
