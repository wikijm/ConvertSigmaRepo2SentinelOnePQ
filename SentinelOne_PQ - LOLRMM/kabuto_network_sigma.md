```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".kabuto.io" or url.address contains "repairtechsolutions.com/kabuto/") or (event.dns.request contains ".kabuto.io" or event.dns.request contains "repairtechsolutions.com/kabuto/")))
```


# Original Sigma Rule:
```yaml
title: Potential Kabuto RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.kabuto.io'
    - repairtechsolutions.com/kabuto/
  condition: selection
id: 7748836e-1d1a-4c37-8d82-b9ef3f50764c
status: experimental
description: Detects potential network activity of Kabuto RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Kabuto
level: medium
```
