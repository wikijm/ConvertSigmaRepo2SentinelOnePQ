```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".teamviewer.com" or url.address contains "router15.teamviewer.com" or url.address contains "client.teamviewer.com" or url.address contains "taf.teamviewer.com") or (event.dns.request contains ".teamviewer.com" or event.dns.request contains "router15.teamviewer.com" or event.dns.request contains "client.teamviewer.com" or event.dns.request contains "taf.teamviewer.com")))
```


# Original Sigma Rule:
```yaml
title: Potential TeamViewer RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.teamviewer.com'
    - router15.teamviewer.com
    - client.teamviewer.com
    - taf.teamviewer.com
  condition: selection
id: 298163bf-7c5d-4d8d-b9b7-6f0df2820afc
status: experimental
description: Detects potential network activity of TeamViewer RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of TeamViewer
level: medium
```
