```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".ezhelp.co.kr" or url.address contains "ezhelp.co.kr") or (event.dns.request contains ".ezhelp.co.kr" or event.dns.request contains "ezhelp.co.kr")))
```


# Original Sigma Rule:
```yaml
title: Potential ezHelp RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.ezhelp.co.kr'
    - ezhelp.co.kr
  condition: selection
id: 1c9349b6-941a-4c1f-9ba0-ab78e16f06fa
status: experimental
description: Detects potential network activity of ezHelp RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ezHelp
level: medium
```
