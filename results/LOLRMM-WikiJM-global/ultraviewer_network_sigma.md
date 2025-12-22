```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains " .ultraviewer.net" or url.address contains "ultraviewer.net") or (event.dns.request contains " .ultraviewer.net" or event.dns.request contains "ultraviewer.net")))
```


# Original Sigma Rule:
```yaml
title: Potential UltraViewer RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '* .ultraviewer.net'
    - ultraviewer.net
  condition: selection
id: c0e39e37-f563-46a1-90a7-2a1736c1165c
status: experimental
description: Detects potential network activity of UltraViewer RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of UltraViewer
level: medium
```
