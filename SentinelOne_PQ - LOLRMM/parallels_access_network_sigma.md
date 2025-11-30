```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".parallels.com" or url.address contains "parallels.com/products/ras/try") or (event.dns.request contains ".parallels.com" or event.dns.request contains "parallels.com/products/ras/try")))
```


# Original Sigma Rule:
```yaml
title: Potential Parallels Access RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.parallels.com'
    - parallels.com/products/ras/try
  condition: selection
id: 77e59b05-dafb-45e4-a552-99826ab6f85a
status: experimental
description: Detects potential network activity of Parallels Access RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Parallels Access
level: medium
```
