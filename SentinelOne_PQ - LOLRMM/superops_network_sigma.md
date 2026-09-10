```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".superopsbeta.com" or url.address contains "superops.ai" or url.address contains "serv.superopsalpha.com" or url.address contains ".superops.ai" or url.address contains ".superopsalpha.com") or (event.dns.request contains ".superopsbeta.com" or event.dns.request contains "superops.ai" or event.dns.request contains "serv.superopsalpha.com" or event.dns.request contains ".superops.ai" or event.dns.request contains ".superopsalpha.com")))
```


# Original Sigma Rule:
```yaml
title: Potential SuperOps RMM Tool Network Activity
id: 79d52531-1c2f-4ca7-9625-c5bb6c5db1e2
status: experimental
description: |
    Detects potential network activity of SuperOps RMM tool
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
            - '*.superopsbeta.com'
            - 'superops.ai'
            - 'serv.superopsalpha.com'
            - '*.superops.ai'
            - '*.superopsalpha.com'
    condition: selection
falsepositives:
    - Legitimate use of SuperOps
level: medium
```
