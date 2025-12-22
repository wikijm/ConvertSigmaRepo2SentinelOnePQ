```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "neturo.uplus.co.kr" or event.dns.request contains "neturo.uplus.co.kr"))
```


# Original Sigma Rule:
```yaml
title: Potential Neturo RMM Tool Network Activity
id: d5444bd0-18d8-431e-97dd-ebe0536fe820
status: experimental
description: |
    Detects potential network activity of Neturo RMM tool
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
        DestinationHostname|endswith: neturo.uplus.co.kr
    condition: selection
falsepositives:
    - Legitimate use of Neturo
level: medium
```
