```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "manageengine.com/remote-monitoring-management/" or event.dns.request contains "manageengine.com/remote-monitoring-management/"))
```


# Original Sigma Rule:
```yaml
title: Potential ManageEngine RMM Central RMM Tool Network Activity
id: 82413f33-db83-4780-a098-b58c4f70bad8
status: experimental
description: |
    Detects potential network activity of ManageEngine RMM Central RMM tool
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
        DestinationHostname|endswith: manageengine.com/remote-monitoring-management/
    condition: selection
falsepositives:
    - Legitimate use of ManageEngine RMM Central
level: medium
```
