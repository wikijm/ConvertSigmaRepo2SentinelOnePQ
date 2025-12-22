```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "basecamp.com" or event.dns.request contains "basecamp.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Basecamp RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - basecamp.com
  condition: selection
id: 2287e3d4-9243-4812-9aa9-0db84f6a1ff6
status: experimental
description: Detects potential network activity of Basecamp RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Basecamp
level: medium
```
