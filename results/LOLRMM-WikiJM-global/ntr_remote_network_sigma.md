```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".ntrsupport.com" or event.dns.request contains ".ntrsupport.com"))
```


# Original Sigma Rule:
```yaml
title: Potential NTR Remote RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.ntrsupport.com'
  condition: selection
id: d34f06a0-1823-45ff-a667-43b140058f47
status: experimental
description: Detects potential network activity of NTR Remote RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of NTR Remote
level: medium
```
