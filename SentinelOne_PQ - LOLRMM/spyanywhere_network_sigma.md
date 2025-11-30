```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".spytech-web.com" or url.address contains "spyanywhere.com") or (event.dns.request contains ".spytech-web.com" or event.dns.request contains "spyanywhere.com")))
```


# Original Sigma Rule:
```yaml
title: Potential SpyAnywhere RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.spytech-web.com'
    - spyanywhere.com
  condition: selection
id: 1e8c6d41-cfc1-4912-92eb-5eb4a55f8b85
status: experimental
description: Detects potential network activity of SpyAnywhere RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of SpyAnywhere
level: medium
```
