```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "app.pdq.com" or url.address contains "cfcdn.pdq.com" or url.address="*pdqinstallers.*.r2.cloudflarestorage.com") or (event.dns.request contains "app.pdq.com" or event.dns.request contains "cfcdn.pdq.com" or event.dns.request="*pdqinstallers.*.r2.cloudflarestorage.com")))
```


# Original Sigma Rule:
```yaml
title: Potential PDQ Connect RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - app.pdq.com
    - cfcdn.pdq.com
    - pdqinstallers.*.r2.cloudflarestorage.com
  condition: selection
id: e27c6d0b-9d16-4eb3-9abd-8ba0a2cc0f6e
status: experimental
description: Detects potential network activity of PDQ Connect RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of PDQ Connect
level: medium
```
