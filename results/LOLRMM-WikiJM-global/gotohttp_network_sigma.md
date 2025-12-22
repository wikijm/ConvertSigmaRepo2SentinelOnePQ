```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".gotohttp.com" or url.address contains "gotohttp.com") or (event.dns.request contains ".gotohttp.com" or event.dns.request contains "gotohttp.com")))
```


# Original Sigma Rule:
```yaml
title: Potential GotoHTTP RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.gotohttp.com'
    - gotohttp.com
  condition: selection
id: 0ab632b8-05a4-4272-a55d-b53bf94ed676
status: experimental
description: Detects potential network activity of GotoHTTP RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of GotoHTTP
level: medium
```
