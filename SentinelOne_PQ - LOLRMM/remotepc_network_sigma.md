```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".remotedesktop.com" or url.address contains ".remotepc.com" or url.address contains "www.remotepc.com" or url.address contains "remotepc.com") or (event.dns.request contains ".remotedesktop.com" or event.dns.request contains ".remotepc.com" or event.dns.request contains "www.remotepc.com" or event.dns.request contains "remotepc.com")))
```


# Original Sigma Rule:
```yaml
title: Potential RemotePC RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.remotedesktop.com'
    - '*.remotepc.com'
    - www.remotepc.com
    - remotepc.com
  condition: selection
id: fa8e726b-d853-4ac5-9d88-905be2962b0b
status: experimental
description: Detects potential network activity of RemotePC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RemotePC
level: medium
```
