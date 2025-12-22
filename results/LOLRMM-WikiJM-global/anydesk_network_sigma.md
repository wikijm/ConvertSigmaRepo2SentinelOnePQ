```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "boot.net.anydesk.com" or url.address contains "relay-[a-f0-9]{8}.net.anydesk.com:443" or url.address contains ".anydesk.com") or (event.dns.request contains "boot.net.anydesk.com" or event.dns.request contains "relay-[a-f0-9]{8}.net.anydesk.com:443" or event.dns.request contains ".anydesk.com")))
```


# Original Sigma Rule:
```yaml
title: Potential AnyDesk RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - boot.net.anydesk.com
    - relay-[a-f0-9]{8}.net.anydesk.com:443
    - '*.anydesk.com'
  condition: selection
id: bf3b1c02-8383-40df-8f5b-14e4a1e4fafe
status: experimental
description: Detects potential network activity of AnyDesk RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of AnyDesk
level: medium
```
