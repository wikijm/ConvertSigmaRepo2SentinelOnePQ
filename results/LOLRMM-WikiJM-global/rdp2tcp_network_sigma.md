```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "github.com/V-E-O/rdp2tcp") or (event.dns.request contains "user_managed" or event.dns.request contains "github.com/V-E-O/rdp2tcp")))
```


# Original Sigma Rule:
```yaml
title: Potential rdp2tcp RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - github.com/V-E-O/rdp2tcp
  condition: selection
id: a378c29e-4c16-48a0-bf97-74cd91c1090e
status: experimental
description: Detects potential network activity of rdp2tcp RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of rdp2tcp
level: medium
```
