```sql
// Translated content (automatically translated on 21-05-2025 00:52:27):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "portal.ehorus.com" or event.dns.request contains "portal.ehorus.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Pandora RC (eHorus) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - portal.ehorus.com
  condition: selection
id: 9a1e3e4b-16fd-4465-afab-39614fd0132b
status: experimental
description: Detects potential network activity of Pandora RC (eHorus) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Pandora RC (eHorus)
level: medium
```
