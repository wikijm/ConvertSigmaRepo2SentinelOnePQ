```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "pilixo.com" or url.address contains "download.pilixo.com" or url.address contains ".pilixo.com") or (event.dns.request contains "pilixo.com" or event.dns.request contains "download.pilixo.com" or event.dns.request contains ".pilixo.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Pilixo RMM Tool Network Activity
id: 292ad909-5053-4e59-a922-af160a9f3c97
status: experimental
description: |
    Detects potential network activity of Pilixo RMM tool
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
            - 'pilixo.com'
            - 'download.pilixo.com'
            - '*.pilixo.com'
    condition: selection
falsepositives:
    - Legitimate use of Pilixo
level: medium
```
