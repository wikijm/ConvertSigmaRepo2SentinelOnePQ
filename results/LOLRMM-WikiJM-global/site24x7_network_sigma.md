```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address="*plus*.site24x7.com" or url.address="*plus*.site24x7.eu" or url.address="*plus*.site24x7.in" or url.address="*plus*.site24x7.cn" or url.address="*plus*.site24x7.net.au" or url.address contains "site24x7.com/msp") or (event.dns.request="*plus*.site24x7.com" or event.dns.request="*plus*.site24x7.eu" or event.dns.request="*plus*.site24x7.in" or event.dns.request="*plus*.site24x7.cn" or event.dns.request="*plus*.site24x7.net.au" or event.dns.request contains "site24x7.com/msp")))
```


# Original Sigma Rule:
```yaml
title: Potential Site24x7 RMM Tool Network Activity
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
id: d81c6910-6e18-47ad-84f1-eca46efba94e
status: experimental
description: Detects potential network activity of Site24x7 RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Site24x7
level: medium
```
