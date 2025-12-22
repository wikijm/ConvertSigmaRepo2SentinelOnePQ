```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "remoteutilities.com" or event.dns.request contains "remoteutilities.com"))
```


# Original Sigma Rule:
```yaml
title: Potential RemoteUtilities RMM Tool Network Activity
id: 3b420f86-5285-40a3-829e-a86532bb4c65
status: experimental
description: |
    Detects potential network activity of RemoteUtilities RMM tool
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
        DestinationHostname|endswith: remoteutilities.com
    condition: selection
falsepositives:
    - Legitimate use of RemoteUtilities
level: medium
```
