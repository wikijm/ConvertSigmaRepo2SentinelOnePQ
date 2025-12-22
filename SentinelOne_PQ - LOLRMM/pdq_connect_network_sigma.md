```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "app.pdq.com" or url.address contains "cfcdn.pdq.com" or url.address="*pdqinstallers.*.r2.cloudflarestorage.com") or (event.dns.request contains "app.pdq.com" or event.dns.request contains "cfcdn.pdq.com" or event.dns.request="*pdqinstallers.*.r2.cloudflarestorage.com")))
```


# Original Sigma Rule:
```yaml
title: Potential PDQ Connect RMM Tool Network Activity
id: 89443d65-866c-4fde-8873-7e740f53c46a
status: experimental
description: |
    Detects potential network activity of PDQ Connect RMM tool
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
        DestinationHostname|endswith:
            - app.pdq.com
            - cfcdn.pdq.com
            - pdqinstallers.*.r2.cloudflarestorage.com
    condition: selection
falsepositives:
    - Legitimate use of PDQ Connect
level: medium
```
