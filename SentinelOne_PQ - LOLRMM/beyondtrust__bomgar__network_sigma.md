```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".beyondtrustcloud.com" or url.address contains ".bomgarcloud.com" or url.address contains "bomgarcloud.com") or (event.dns.request contains ".beyondtrustcloud.com" or event.dns.request contains ".bomgarcloud.com" or event.dns.request contains "bomgarcloud.com")))
```


# Original Sigma Rule:
```yaml
title: Potential BeyondTrust (Bomgar) RMM Tool Network Activity
id: 694d14f2-df79-4aaa-b59f-ee94278977fc
status: experimental
description: |
    Detects potential network activity of BeyondTrust (Bomgar) RMM tool
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
            - '*.beyondtrustcloud.com'
            - '*.bomgarcloud.com'
            - 'bomgarcloud.com'
    condition: selection
falsepositives:
    - Legitimate use of BeyondTrust (Bomgar)
level: medium
```
