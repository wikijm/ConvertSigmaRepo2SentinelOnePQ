```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".itsm-us1.comodo.com" or url.address contains "mdmsupport.comodo.com" or url.address contains "one.comodo.com") or (event.dns.request contains ".itsm-us1.comodo.com" or event.dns.request contains "mdmsupport.comodo.com" or event.dns.request contains "one.comodo.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Comodo RMM RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.itsm-us1.comodo.com'
    - '*mdmsupport.comodo.com'
    - one.comodo.com
  condition: selection
id: 6f6593a9-b2fa-4a29-9fdf-67972e2af588
status: experimental
description: Detects potential network activity of Comodo RMM RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Comodo RMM
level: medium
```
