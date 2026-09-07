```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".ezhelp.co.kr" or url.address contains "ezhelp.co.kr") or (event.dns.request contains ".ezhelp.co.kr" or event.dns.request contains "ezhelp.co.kr")))
```


# Original Sigma Rule:
```yaml
title: Potential ezHelp RMM Tool Network Activity
id: c2b0145b-04ca-4d20-9601-782f90628b95
status: experimental
description: |
    Detects potential network activity of ezHelp RMM tool
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
            - '*.ezhelp.co.kr'
            - 'ezhelp.co.kr'
    condition: selection
falsepositives:
    - Legitimate use of ezHelp
level: medium
```
