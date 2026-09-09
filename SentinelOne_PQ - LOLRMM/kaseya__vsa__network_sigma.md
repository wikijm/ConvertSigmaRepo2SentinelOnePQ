```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "deploy01.kaseya.com" or url.address contains "managedsupport.kaseya.net" or url.address contains ".managedsupport.kaseya.net" or url.address contains ".kaseya.net" or url.address contains "kaseya.com") or (event.dns.request contains "deploy01.kaseya.com" or event.dns.request contains "managedsupport.kaseya.net" or event.dns.request contains ".managedsupport.kaseya.net" or event.dns.request contains ".kaseya.net" or event.dns.request contains "kaseya.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Kaseya (VSA) RMM Tool Network Activity
id: b50291cd-fc39-4416-af8e-e53be7c6eb51
status: experimental
description: |
    Detects potential network activity of Kaseya (VSA) RMM tool
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
            - 'deploy01.kaseya.com'
            - 'managedsupport.kaseya.net'
            - '*.managedsupport.kaseya.net'
            - '*.kaseya.net'
            - 'kaseya.com'
    condition: selection
falsepositives:
    - Legitimate use of Kaseya (VSA)
level: medium
```
