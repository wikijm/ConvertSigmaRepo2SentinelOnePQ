```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "skyfex.com" or url.address contains "deskroll.com" or url.address contains ".deskroll.com") or (event.dns.request contains "skyfex.com" or event.dns.request contains "deskroll.com" or event.dns.request contains ".deskroll.com")))
```


# Original Sigma Rule:
```yaml
title: Potential SkyFex RMM Tool Network Activity
id: c7d7cb02-e36f-4f83-8927-acacbc54db0a
status: experimental
description: |
    Detects potential network activity of SkyFex RMM tool
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
            - 'skyfex.com'
            - 'deskroll.com'
            - '*.deskroll.com'
    condition: selection
falsepositives:
    - Legitimate use of SkyFex
level: medium
```
