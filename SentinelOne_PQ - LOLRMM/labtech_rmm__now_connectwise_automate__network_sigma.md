```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "connectwise.com" or event.dns.request contains "connectwise.com"))
```


# Original Sigma Rule:
```yaml
title: Potential LabTech RMM (Now ConnectWise Automate) RMM Tool Network Activity
id: 68683c0f-ea95-4c02-a77e-2bf328ce4678
status: experimental
description: |
    Detects potential network activity of LabTech RMM (Now ConnectWise Automate) RMM tool
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
        DestinationHostname|endswith: connectwise.com
    condition: selection
falsepositives:
    - Legitimate use of LabTech RMM (Now ConnectWise Automate)
level: medium
```
