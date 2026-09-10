```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".xeox.com" or url.address contains "xeox.com") or (event.dns.request contains ".xeox.com" or event.dns.request contains "xeox.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Xeox RMM Tool Network Activity
id: 8505dded-1605-4b90-bcd4-c6d833c816c4
status: experimental
description: |
    Detects potential network activity of Xeox RMM tool
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
            - '*.xeox.com'
            - 'xeox.com'
    condition: selection
falsepositives:
    - Legitimate use of Xeox
level: medium
```
