```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".spytech-web.com" or url.address contains "spyanywhere.com") or (event.dns.request contains ".spytech-web.com" or event.dns.request contains "spyanywhere.com")))
```


# Original Sigma Rule:
```yaml
title: Potential SpyAnywhere RMM Tool Network Activity
id: 45151543-012c-4875-b809-cd3878b63def
status: experimental
description: |
    Detects potential network activity of SpyAnywhere RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - '*.spytech-web.com'
            - 'spyanywhere.com'
    condition: selection
falsepositives:
    - Legitimate use of SpyAnywhere
level: medium
```
