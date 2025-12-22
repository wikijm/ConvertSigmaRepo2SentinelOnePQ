```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address="*plus*.site24x7.com" or url.address="*plus*.site24x7.eu" or url.address="*plus*.site24x7.in" or url.address="*plus*.site24x7.cn" or url.address="*plus*.site24x7.net.au" or url.address contains "site24x7.com/msp") or (event.dns.request="*plus*.site24x7.com" or event.dns.request="*plus*.site24x7.eu" or event.dns.request="*plus*.site24x7.in" or event.dns.request="*plus*.site24x7.cn" or event.dns.request="*plus*.site24x7.net.au" or event.dns.request contains "site24x7.com/msp")))
```


# Original Sigma Rule:
```yaml
title: Potential Site24x7 RMM Tool Network Activity
id: 5524bfef-3644-44dd-84a9-0e6116a35e78
status: experimental
description: |
    Detects potential network activity of Site24x7 RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - plus*.site24x7.com
            - plus*.site24x7.eu
            - plus*.site24x7.in
            - plus*.site24x7.cn
            - plus*.site24x7.net.au
            - site24x7.com/msp
    condition: selection
falsepositives:
    - Legitimate use of Site24x7
level: medium
```
