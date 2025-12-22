```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "login.tailscale.com" or url.address contains "login.tailscale.com" or url.address contains "docs.tacticalrmm.com") or (event.dns.request contains "login.tailscale.com" or event.dns.request contains "login.tailscale.com" or event.dns.request contains "docs.tacticalrmm.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Tactical RMM RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - login.tailscale.com
    - login.tailscale.com
    - docs.tacticalrmm.com
  condition: selection
id: 607074fd-7a44-49eb-948a-8bf893afc142
status: experimental
description: Detects potential network activity of Tactical RMM RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Tactical RMM
level: medium
```
