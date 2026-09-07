```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "hoptodesk.com" or url.address contains "api.hoptodesk.com" or url.address contains "signal.hoptodesk.com" or url.address contains "turn.hoptodesk.com" or url.address contains "download.hoptodesk.com" or url.address contains "www.hoptodesk.com") or (event.dns.request contains "hoptodesk.com" or event.dns.request contains "api.hoptodesk.com" or event.dns.request contains "signal.hoptodesk.com" or event.dns.request contains "turn.hoptodesk.com" or event.dns.request contains "download.hoptodesk.com" or event.dns.request contains "www.hoptodesk.com")))
```


# Original Sigma Rule:
```yaml
title: Potential HopToDesk RMM Tool Network Activity
id: 68fd1e88-4536-42ee-8517-cd8fbc3df925
status: experimental
description: |
    Detects potential network activity of HopToDesk RMM tool
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
            - 'hoptodesk.com'
            - 'api.hoptodesk.com'
            - 'signal.hoptodesk.com'
            - 'turn.hoptodesk.com'
            - 'download.hoptodesk.com'
            - 'www.hoptodesk.com'
    condition: selection
falsepositives:
    - Legitimate use of HopToDesk
level: medium
```
