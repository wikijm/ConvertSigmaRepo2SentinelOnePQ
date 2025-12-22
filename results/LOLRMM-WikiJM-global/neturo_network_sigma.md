```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "neturo.uplus.co.kr" or event.dns.request contains "neturo.uplus.co.kr"))
```


# Original Sigma Rule:
```yaml
title: Potential Neturo RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - neturo.uplus.co.kr
  condition: selection
id: 39327f41-3a98-4a53-ac28-6b610b138cba
status: experimental
description: Detects potential network activity of Neturo RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Neturo
level: medium
```
