```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".247ithelp.com" or event.dns.request contains ".247ithelp.com"))
```


# Original Sigma Rule:
```yaml
title: Potential 247ithelp.com (ConnectWise) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.247ithelp.com'
  condition: selection
id: 8248627a-264d-423c-b684-f96a5792a332
status: experimental
description: Detects potential network activity of 247ithelp.com (ConnectWise) RMM
  tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of 247ithelp.com (ConnectWise)
level: medium
```
