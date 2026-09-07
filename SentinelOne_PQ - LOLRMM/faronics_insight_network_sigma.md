```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "faronics.com" or url.address contains "www.faronics.com" or url.address contains "support.faronics.com" or url.address contains "docs.faronics.com" or url.address contains "user_managed") or (event.dns.request contains "faronics.com" or event.dns.request contains "www.faronics.com" or event.dns.request contains "support.faronics.com" or event.dns.request contains "docs.faronics.com" or event.dns.request contains "user_managed")))
```


# Original Sigma Rule:
```yaml
title: Potential Faronics Insight RMM Tool Network Activity
id: 20f936fa-bbd5-5d5f-adc5-1df7d6342ea0
status: experimental
description: |
    Detects potential network activity of Faronics Insight RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
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
            - 'faronics.com'
            - 'www.faronics.com'
            - 'support.faronics.com'
            - 'docs.faronics.com'
            - 'user_managed'
    condition: selection
falsepositives:
    - Legitimate use of Faronics Insight
level: medium
```
