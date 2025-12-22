```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "goverlan.com") or (event.dns.request contains "user_managed" or event.dns.request contains "goverlan.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Goverlan RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - goverlan.com
  condition: selection
id: 4564a8c4-c547-47dd-85e4-051f56cc080d
status: experimental
description: Detects potential network activity of Goverlan RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Goverlan
level: medium
```
