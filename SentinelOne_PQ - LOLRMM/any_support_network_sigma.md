```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".anysupport.net" or event.dns.request contains ".anysupport.net"))
```


# Original Sigma Rule:
```yaml
title: Potential Any Support RMM Tool Network Activity
id: 2266db74-38c4-40ab-b8b2-c3bf041ae11f
status: experimental
description: |
    Detects potential network activity of Any Support RMM tool
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
        DestinationHostname|endswith: '*.anysupport.net'
    condition: selection
falsepositives:
    - Legitimate use of Any Support
level: medium
```
