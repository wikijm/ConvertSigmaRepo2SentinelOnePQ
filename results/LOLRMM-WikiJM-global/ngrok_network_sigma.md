```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "ngrok.com") or (event.dns.request contains "user_managed" or event.dns.request contains "ngrok.com")))
```


# Original Sigma Rule:
```yaml
title: Potential ngrok RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - ngrok.com
  condition: selection
id: 2f94f187-ac51-4e50-a6f5-7f6c3bfa5578
status: experimental
description: Detects potential network activity of ngrok RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ngrok
level: medium
```
