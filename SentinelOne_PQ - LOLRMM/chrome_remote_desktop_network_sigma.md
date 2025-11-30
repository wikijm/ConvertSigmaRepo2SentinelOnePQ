```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "remotedesktop-pa.googleapis.com" or url.address contains "remotedesktop.google.com" or url.address contains "remotedesktop.google.com") or (event.dns.request contains "remotedesktop-pa.googleapis.com" or event.dns.request contains "remotedesktop.google.com" or event.dns.request contains "remotedesktop.google.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Chrome Remote Desktop RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*remotedesktop-pa.googleapis.com'
    - '*remotedesktop.google.com'
    - remotedesktop.google.com
  condition: selection
id: 51447322-5c31-4d35-ac2d-31edbf479644
status: experimental
description: Detects potential network activity of Chrome Remote Desktop RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Chrome Remote Desktop
level: medium
```
