```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".anyviewer.com" or url.address contains ".aomeisoftware.com") or (event.dns.request contains ".anyviewer.com" or event.dns.request contains ".aomeisoftware.com")))
```


# Original Sigma Rule:
```yaml
title: Potential AnyViewer RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.anyviewer.com'
    - '*.aomeisoftware.com'
  condition: selection
id: 856c0541-662b-4403-b712-a787b7ff6ebb
status: experimental
description: Detects potential network activity of AnyViewer RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of AnyViewer
level: medium
```
