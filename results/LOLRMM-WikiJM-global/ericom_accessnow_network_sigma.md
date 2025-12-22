```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "ericom.com") or (event.dns.request contains "user_managed" or event.dns.request contains "ericom.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Ericom AccessNow RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - ericom.com
  condition: selection
id: 1251e733-2e04-4e79-a1fa-4c171f5b0e46
status: experimental
description: Detects potential network activity of Ericom AccessNow RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Ericom AccessNow
level: medium
```
