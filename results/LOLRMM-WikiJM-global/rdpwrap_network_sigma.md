```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "github.com/stascorp/rdpwrap") or (event.dns.request contains "user_managed" or event.dns.request contains "github.com/stascorp/rdpwrap")))
```


# Original Sigma Rule:
```yaml
title: Potential rdpwrap RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - github.com/stascorp/rdpwrap
  condition: selection
id: 572e0b60-49b2-436f-a35c-4d8124455479
status: experimental
description: Detects potential network activity of rdpwrap RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of rdpwrap
level: medium
```
