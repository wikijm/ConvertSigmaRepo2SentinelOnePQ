```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "todesk.com" or url.address contains ".todesk.com" or url.address contains ".todesk.com" or url.address contains "todesktop.com") or (event.dns.request contains "todesk.com" or event.dns.request contains ".todesk.com" or event.dns.request contains ".todesk.com" or event.dns.request contains "todesktop.com")))
```


# Original Sigma Rule:
```yaml
title: Potential ToDesk RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - todesk.com
    - '*.todesk.com'
    - '*.todesk.com'
    - todesktop.com
  condition: selection
id: c50ae6aa-3864-4654-bce8-4b9a24a962a6
status: experimental
description: Detects potential network activity of ToDesk RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ToDesk
level: medium
```
