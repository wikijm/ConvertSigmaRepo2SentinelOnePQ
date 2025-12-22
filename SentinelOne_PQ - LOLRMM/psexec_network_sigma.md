```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "user_managed" or event.dns.request contains "user_managed"))
```


# Original Sigma Rule:
```yaml
title: Potential PSEXEC RMM Tool Network Activity
id: 13e68481-5956-4632-a802-d8aa511b31b1
status: experimental
description: |
    Detects potential network activity of PSEXEC RMM tool
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
        DestinationHostname|endswith: user_managed
    condition: selection
falsepositives:
    - Legitimate use of PSEXEC
level: medium
```
