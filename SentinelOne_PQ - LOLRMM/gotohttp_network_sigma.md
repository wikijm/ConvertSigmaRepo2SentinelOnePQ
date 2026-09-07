```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".gotohttp.com" or url.address contains "gotohttp.com") or (event.dns.request contains ".gotohttp.com" or event.dns.request contains "gotohttp.com")))
```


# Original Sigma Rule:
```yaml
title: Potential GotoHTTP RMM Tool Network Activity
id: 1b6aea94-3773-4566-9ad5-073e438c94a8
status: experimental
description: |
    Detects potential network activity of GotoHTTP RMM tool
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
            - '*.gotohttp.com'
            - 'gotohttp.com'
    condition: selection
falsepositives:
    - Legitimate use of GotoHTTP
level: medium
```
