```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".hostedrmm.com" or event.dns.request contains ".hostedrmm.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Connectwise Automate (LabTech) RMM Tool Network Activity
id: a964c1ea-0038-41c0-ba27-346c80e7e31c
status: experimental
description: |
    Detects potential network activity of Connectwise Automate (LabTech) RMM tool
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
        DestinationHostname|endswith: '*.hostedrmm.com'
    condition: selection
falsepositives:
    - Legitimate use of Connectwise Automate (LabTech)
level: medium
```
