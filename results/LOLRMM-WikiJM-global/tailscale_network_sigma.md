```sql
// Translated content (automatically translated on 29-01-2026 02:04:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".tailscale.com" or url.address contains ".tailscale.io" or url.address contains "tailscale.com") or (event.dns.request contains ".tailscale.com" or event.dns.request contains ".tailscale.io" or event.dns.request contains "tailscale.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Tailscale RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.tailscale.com'
    - '*.tailscale.io'
    - tailscale.com
  condition: selection
id: a4f61da1-8b97-46ff-8814-00d492e00b18
status: experimental
description: Detects potential network activity of Tailscale RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Tailscale
level: medium
```
