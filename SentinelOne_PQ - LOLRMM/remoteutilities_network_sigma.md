```sql
// Translated content (automatically translated on 28-05-2025 00:52:25):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "remoteutilities.com" or event.dns.request contains "remoteutilities.com"))
```


# Original Sigma Rule:
```yaml
title: Potential RemoteUtilities RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - remoteutilities.com
  condition: selection
id: 073bc5bd-92d0-46ee-b021-cc17b9aa9d5a
status: experimental
description: Detects potential network activity of RemoteUtilities RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RemoteUtilities
level: medium
```
