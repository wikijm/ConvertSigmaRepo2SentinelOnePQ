```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "logmein-gateway.com" or url.address contains ".logmein.com" or url.address contains ".logmein.eu" or url.address contains "logmeinrescue.com" or url.address contains ".logmeininc.com") or (event.dns.request contains "logmein-gateway.com" or event.dns.request contains ".logmein.com" or event.dns.request contains ".logmein.eu" or event.dns.request contains "logmeinrescue.com" or event.dns.request contains ".logmeininc.com")))
```


# Original Sigma Rule:
```yaml
title: Potential LogMeIn RMM Tool Network Activity
id: 7aeba9ce-5883-4ea6-bc0c-394af2774b49
status: experimental
description: |
    Detects potential network activity of LogMeIn RMM tool
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
            - 'logmein-gateway.com'
            - '*.logmein.com'
            - '*.logmein.eu'
            - 'logmeinrescue.com'
            - '*.logmeininc.com'
    condition: selection
falsepositives:
    - Legitimate use of LogMeIn
level: medium
```
