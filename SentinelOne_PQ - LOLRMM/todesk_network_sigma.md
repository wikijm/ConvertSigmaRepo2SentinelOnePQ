```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "todesk.com" or url.address contains ".todesk.com") or (event.dns.request contains "todesk.com" or event.dns.request contains ".todesk.com")))
```


# Original Sigma Rule:
```yaml
title: Potential ToDesk RMM Tool Network Activity
id: 8c9c2180-ab76-47b7-a82a-1c64c451c851
status: experimental
description: |
    Detects potential network activity of ToDesk RMM tool
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
            - 'todesk.com'
            - '*.todesk.com'
    condition: selection
falsepositives:
    - Legitimate use of ToDesk
level: medium
```
