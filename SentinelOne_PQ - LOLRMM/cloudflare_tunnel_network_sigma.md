```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "cloudflare.com/products/tunnel/" or event.dns.request contains "cloudflare.com/products/tunnel/"))
```


# Original Sigma Rule:
```yaml
title: Potential CloudFlare Tunnel RMM Tool Network Activity
id: e04b9b34-e501-49d9-89f4-f9ae4534131f
status: experimental
description: |
    Detects potential network activity of CloudFlare Tunnel RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith: cloudflare.com/products/tunnel/
    condition: selection
falsepositives:
    - Legitimate use of CloudFlare Tunnel
level: medium
```
