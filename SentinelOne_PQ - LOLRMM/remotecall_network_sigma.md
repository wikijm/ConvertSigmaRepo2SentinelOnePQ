```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".remotecall.com" or url.address contains ".startsupport.com" or url.address contains "remotecall.com") or (event.dns.request contains ".remotecall.com" or event.dns.request contains ".startsupport.com" or event.dns.request contains "remotecall.com")))
```


# Original Sigma Rule:
```yaml
title: Potential RemoteCall RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.remotecall.com'
    - '*.startsupport.com'
    - remotecall.com
  condition: selection
id: 79c87892-d0a9-4a57-836b-d4ee63ec5187
status: experimental
description: Detects potential network activity of RemoteCall RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RemoteCall
level: medium
```
