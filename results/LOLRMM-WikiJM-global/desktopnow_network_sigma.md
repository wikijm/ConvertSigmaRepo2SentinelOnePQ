```sql
// Translated content (automatically translated on 29-01-2026 02:04:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".nchuser.com" or event.dns.request contains ".nchuser.com"))
```


# Original Sigma Rule:
```yaml
title: Potential DesktopNow RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.nchuser.com'
  condition: selection
id: 2541974e-61bc-4869-b902-f828f3db1a2d
status: experimental
description: Detects potential network activity of DesktopNow RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of DesktopNow
level: medium
```
