```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".fastviewer.com" or url.address contains "fastviewer.com") or (event.dns.request contains ".fastviewer.com" or event.dns.request contains "fastviewer.com")))
```


# Original Sigma Rule:
```yaml
title: Potential FastViewer RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.fastviewer.com'
    - fastviewer.com
  condition: selection
id: 2bd1088d-19c5-4d3d-a22b-bf56245c9cc8
status: experimental
description: Detects potential network activity of FastViewer RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of FastViewer
level: medium
```
