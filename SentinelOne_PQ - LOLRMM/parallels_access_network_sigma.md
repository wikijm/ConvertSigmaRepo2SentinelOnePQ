```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".parallels.com" or event.dns.request contains ".parallels.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Parallels Access RMM Tool Network Activity
id: 30ddd92c-43ea-47bc-9580-a2a5e9184321
status: experimental
description: |
    Detects potential network activity of Parallels Access RMM tool
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
        DestinationHostname|endswith: '*.parallels.com'
    condition: selection
falsepositives:
    - Legitimate use of Parallels Access
level: medium
```
