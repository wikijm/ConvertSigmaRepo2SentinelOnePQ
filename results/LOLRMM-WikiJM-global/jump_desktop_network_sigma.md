```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains ".jumpdesktop.com" or url.address contains "jumpdesktop.com" or url.address contains "jumpto.me" or url.address contains ".jumpto.me") or (event.dns.request contains ".jumpdesktop.com" or event.dns.request contains "jumpdesktop.com" or event.dns.request contains "jumpto.me" or event.dns.request contains ".jumpto.me")))
```


# Original Sigma Rule:
```yaml
title: Potential Jump Desktop RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.jumpdesktop.com'
    - jumpdesktop.com
    - jumpto.me
    - '*.jumpto.me'
  condition: selection
id: 5e78e6b3-b646-460b-8407-7135a837bd9f
status: experimental
description: Detects potential network activity of Jump Desktop RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Jump Desktop
level: medium
```
