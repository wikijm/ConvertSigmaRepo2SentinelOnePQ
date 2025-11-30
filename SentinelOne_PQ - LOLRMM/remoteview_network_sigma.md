```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "content.rview.com" or url.address contains ".rview.com" or url.address contains "content.rview.com") or (event.dns.request contains "content.rview.com" or event.dns.request contains ".rview.com" or event.dns.request contains "content.rview.com")))
```


# Original Sigma Rule:
```yaml
title: Potential RemoteView RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*content.rview.com'
    - '*.rview.com'
    - content.rview.com
  condition: selection
id: f9311795-53c6-4b41-8633-2dd5848a5aaf
status: experimental
description: Detects potential network activity of RemoteView RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RemoteView
level: medium
```
