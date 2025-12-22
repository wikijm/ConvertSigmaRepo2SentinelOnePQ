```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "rustdesk.com" or url.address contains "user_managed" or url.address contains "web.rustdesk.com") or (event.dns.request contains "rustdesk.com" or event.dns.request contains "user_managed" or event.dns.request contains "web.rustdesk.com")))
```


# Original Sigma Rule:
```yaml
title: Potential RustDesk RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - rustdesk.com
    - user_managed
    - web.rustdesk.com
  condition: selection
id: 9dfd4863-c198-462d-95d4-44c654d3a6b4
status: experimental
description: Detects potential network activity of RustDesk RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RustDesk
level: medium
```
