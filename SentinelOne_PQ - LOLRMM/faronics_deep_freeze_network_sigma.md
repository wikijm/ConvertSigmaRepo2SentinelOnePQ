```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "deepfreeze.com" or url.address contains "www.deepfreeze.com" or url.address contains "faronicscloud.com" or url.address contains "cloud.faronics.com" or url.address contains "upd.faronicslabs.com" or url.address contains "faronics.com" or url.address contains "www.faronics.com") or (event.dns.request contains "deepfreeze.com" or event.dns.request contains "www.deepfreeze.com" or event.dns.request contains "faronicscloud.com" or event.dns.request contains "cloud.faronics.com" or event.dns.request contains "upd.faronicslabs.com" or event.dns.request contains "faronics.com" or event.dns.request contains "www.faronics.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Faronics Deep Freeze RMM Tool Network Activity
id: 609bd342-8772-59a6-aa39-e7be6cac0763
status: experimental
description: |
    Detects potential network activity of Faronics Deep Freeze RMM tool
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
            - 'deepfreeze.com'
            - 'www.deepfreeze.com'
            - 'faronicscloud.com'
            - 'cloud.faronics.com'
            - 'upd.faronicslabs.com'
            - 'faronics.com'
            - 'www.faronics.com'
    condition: selection
falsepositives:
    - Legitimate use of Faronics Deep Freeze
level: medium
```
