```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".247ithelp.com" or event.dns.request contains ".247ithelp.com"))
```


# Original Sigma Rule:
```yaml
title: Potential 247ithelp.com (ConnectWise) RMM Tool Network Activity
id: 43e31a0e-0682-4a5b-9031-2c36d6cf829b
status: experimental
description: |
    Detects potential network activity of 247ithelp.com (ConnectWise) RMM tool
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
        DestinationHostname|endswith: '*.247ithelp.com'
    condition: selection
falsepositives:
    - Legitimate use of 247ithelp.com (ConnectWise)
level: medium
```
