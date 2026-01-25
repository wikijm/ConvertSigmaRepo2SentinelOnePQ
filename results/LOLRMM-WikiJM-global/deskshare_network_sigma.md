```sql
// Translated content (automatically translated on 25-01-2026 01:58:47):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "user_managed" or event.dns.request contains "user_managed"))
```


# Original Sigma Rule:
```yaml
title: Potential DeskShare RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
  condition: selection
id: cc4d6f65-b7c0-419a-97d2-107595b325cf
status: experimental
description: Detects potential network activity of DeskShare RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of DeskShare
level: medium
```
