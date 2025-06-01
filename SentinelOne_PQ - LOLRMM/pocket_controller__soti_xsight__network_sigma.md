```sql
// Translated content (automatically translated on 01-06-2025 01:03:06):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "soti.net" or event.dns.request contains "soti.net"))
```


# Original Sigma Rule:
```yaml
title: Potential Pocket Controller (Soti Xsight) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*soti.net'
  condition: selection
id: e49aea52-4057-4ebf-9c22-3424e1c52632
status: experimental
description: Detects potential network activity of Pocket Controller (Soti Xsight)
  RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Pocket Controller (Soti Xsight)
level: medium
```
