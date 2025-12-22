```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address="*asapi*.aweray.net" or url.address contains "client-api.aweray.com") or (event.dns.request="*asapi*.aweray.net" or event.dns.request contains "client-api.aweray.com")))
```


# Original Sigma Rule:
```yaml
title: Potential AweRay RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - asapi*.aweray.net
    - client-api.aweray.com
  condition: selection
id: f20a6812-5634-43bd-9d1e-1ecb60c11430
status: experimental
description: Detects potential network activity of AweRay RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of AweRay
level: medium
```
