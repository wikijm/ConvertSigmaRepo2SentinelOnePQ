```sql
// Translated content (automatically translated on 24-05-2025 01:27:12):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "acceo.com/turbomeeting/") or (event.dns.request contains "user_managed" or event.dns.request contains "acceo.com/turbomeeting/")))
```


# Original Sigma Rule:
```yaml
title: Potential TurboMeeting RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - acceo.com/turbomeeting/
  condition: selection
id: f1d46c89-a357-4a9c-9dee-e5d35dcb683a
status: experimental
description: Detects potential network activity of TurboMeeting RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of TurboMeeting
level: medium
```
