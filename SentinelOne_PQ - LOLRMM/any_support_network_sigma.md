```sql
// Translated content (automatically translated on 02-05-2025 01:36:20):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains ".anysupport.net" or event.dns.request contains ".anysupport.net"))
```


# Original Sigma Rule:
```yaml
title: Potential Any Support RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.anysupport.net'
  condition: selection
id: 734b4e22-2195-4355-8a09-d6a2ef3ea908
status: experimental
description: Detects potential network activity of Any Support RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Any Support
level: medium
```
