```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "remotepass.com" or event.dns.request contains "remotepass.com"))
```


# Original Sigma Rule:
```yaml
title: Potential RemotePass RMM Tool Network Activity
id: f4461751-f222-4de0-9993-9f6b7c4a2e8b
status: experimental
description: |
    Detects potential network activity of RemotePass RMM tool
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
        DestinationHostname|endswith: remotepass.com
    condition: selection
falsepositives:
    - Legitimate use of RemotePass
level: medium
```
