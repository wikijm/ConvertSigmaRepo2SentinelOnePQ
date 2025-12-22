```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "cloudflare.com/products/tunnel/" or event.dns.request contains "cloudflare.com/products/tunnel/"))
```


# Original Sigma Rule:
```yaml
title: Potential CloudFlare Tunnel RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - cloudflare.com/products/tunnel/
  condition: selection
id: f64ebd79-45b1-4ed4-8dad-571d0bca51b6
status: experimental
description: Detects potential network activity of CloudFlare Tunnel RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of CloudFlare Tunnel
level: medium
```
