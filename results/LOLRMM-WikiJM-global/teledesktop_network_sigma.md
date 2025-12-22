```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "tele-desk.com") or (event.dns.request contains "user_managed" or event.dns.request contains "tele-desk.com")))
```


# Original Sigma Rule:
```yaml
title: Potential TeleDesktop RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - tele-desk.com
  condition: selection
id: 81a1ee71-af2f-4190-8402-8f48876a11fa
status: experimental
description: Detects potential network activity of TeleDesktop RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of TeleDesktop
level: medium
```
