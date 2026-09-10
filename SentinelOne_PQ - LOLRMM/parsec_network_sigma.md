```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "parsec.app" or url.address contains "parsec.gg" or url.address contains ".parsec.app") or (event.dns.request contains "parsec.app" or event.dns.request contains "parsec.gg" or event.dns.request contains ".parsec.app")))
```


# Original Sigma Rule:
```yaml
title: Potential Parsec RMM Tool Network Activity
id: ee67c1ca-b3d3-4cda-b751-911181fc13a3
status: experimental
description: |
    Detects potential network activity of Parsec RMM tool
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
            - 'parsec.app'
            - 'parsec.gg'
            - '*.parsec.app'
    condition: selection
falsepositives:
    - Legitimate use of Parsec
level: medium
```
