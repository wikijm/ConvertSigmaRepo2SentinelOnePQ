```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "encapto.com" or event.dns.request contains "encapto.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Encapto RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - encapto.com
  condition: selection
id: 78836ae6-3dc5-4271-9643-7d6f02e60b4b
status: experimental
description: Detects potential network activity of Encapto RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Encapto
level: medium
```
