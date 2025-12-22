```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "atled.syspectr.com" or url.address contains "app.syspectr.com") or (event.dns.request contains "atled.syspectr.com" or event.dns.request contains "app.syspectr.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Syspectr RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - atled.syspectr.com
    - app.syspectr.com
  condition: selection
id: 1c369a6a-d658-458d-8b8c-8afc2c192e6e
status: experimental
description: Detects potential network activity of Syspectr RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Syspectr
level: medium
```
