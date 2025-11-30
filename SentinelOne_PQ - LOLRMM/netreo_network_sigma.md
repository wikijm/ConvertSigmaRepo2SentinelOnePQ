```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "charon.netreo.net" or url.address contains "activation.netreo.net" or url.address contains ".api.netreo.com" or url.address contains "netreo.com") or (event.dns.request contains "charon.netreo.net" or event.dns.request contains "activation.netreo.net" or event.dns.request contains ".api.netreo.com" or event.dns.request contains "netreo.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Netreo RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - charon.netreo.net
    - activation.netreo.net
    - '*.api.netreo.com'
    - netreo.com
  condition: selection
id: bce122a6-0821-4d9a-953a-2b1e9d5b218b
status: experimental
description: Detects potential network activity of Netreo RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Netreo
level: medium
```
