```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "download.cnet.com/Net-Viewer/3000-2370_4-10034828.html" or event.dns.request contains "download.cnet.com/Net-Viewer/3000-2370_4-10034828.html"))
```


# Original Sigma Rule:
```yaml
title: Potential Netviewer RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - download.cnet.com/Net-Viewer/3000-2370_4-10034828.html
  condition: selection
id: f861142d-58b1-4c98-a407-83e458a59444
status: experimental
description: Detects potential network activity of Netviewer RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Netviewer
level: medium
```
