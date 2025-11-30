```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".01com.com" or url.address contains "01com.com/imintouch-remote-pc-desktop") or (event.dns.request contains ".01com.com" or event.dns.request contains "01com.com/imintouch-remote-pc-desktop")))
```


# Original Sigma Rule:
```yaml
title: Potential I'm InTouch RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.01com.com'
    - 01com.com/imintouch-remote-pc-desktop
  condition: selection
id: e9c4aa64-be23-4708-a1dd-e8c3661d74e6
status: experimental
description: Detects potential network activity of I'm InTouch RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of I'm InTouch
level: medium
```
