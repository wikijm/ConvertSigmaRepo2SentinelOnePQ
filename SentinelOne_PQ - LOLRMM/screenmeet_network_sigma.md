```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".screenmeet.com" or url.address contains ".scrn.mt") or (event.dns.request contains ".screenmeet.com" or event.dns.request contains ".scrn.mt")))
```


# Original Sigma Rule:
```yaml
title: Potential ScreenMeet RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.screenmeet.com'
    - '*.scrn.mt'
  condition: selection
id: 8a5e7ba1-65ff-4f55-a524-62411a667b65
status: experimental
description: Detects potential network activity of ScreenMeet RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ScreenMeet
level: medium
```
