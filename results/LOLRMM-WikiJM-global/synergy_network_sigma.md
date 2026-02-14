```sql
// Translated content (automatically translated on 14-02-2026 02:04:58):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "user_managed" or event.dns.request contains "user_managed"))
```


# Original Sigma Rule:
```yaml
title: Potential Synergy RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
  condition: selection
id: 8a14773a-b4b5-4d4a-962b-b080c95b7812
status: experimental
description: Detects potential network activity of Synergy RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Synergy
level: medium
```
