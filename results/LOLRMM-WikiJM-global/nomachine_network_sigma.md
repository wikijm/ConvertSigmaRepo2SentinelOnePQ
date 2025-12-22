```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "nomachine.com") or (event.dns.request contains "user_managed" or event.dns.request contains "nomachine.com")))
```


# Original Sigma Rule:
```yaml
title: Potential NoMachine RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - nomachine.com
  condition: selection
id: b80bd471-4420-482d-93c4-d2755a4ed4dc
status: experimental
description: Detects potential network activity of NoMachine RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of NoMachine
level: medium
```
