```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".ntrsupport.com" or event.dns.request contains ".ntrsupport.com"))
```


# Original Sigma Rule:
```yaml
title: Potential NTR Remote RMM Tool Network Activity
id: 2b92af57-0b89-44bd-a475-fe3afb7ba388
status: experimental
description: |
    Detects potential network activity of NTR Remote RMM tool
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
        DestinationHostname|endswith: '*.ntrsupport.com'
    condition: selection
falsepositives:
    - Legitimate use of NTR Remote
level: medium
```
