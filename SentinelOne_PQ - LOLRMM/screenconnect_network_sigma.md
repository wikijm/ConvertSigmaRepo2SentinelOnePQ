```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "control.connectwise.com" or url.address contains ".connectwise.com" or url.address contains ".screenconnect.com") or (event.dns.request contains "control.connectwise.com" or event.dns.request contains ".connectwise.com" or event.dns.request contains ".screenconnect.com")))
```


# Original Sigma Rule:
```yaml
title: Potential ScreenConnect RMM Tool Network Activity
id: 74f512be-1adb-411e-962f-9f759996e8fe
status: experimental
description: |
    Detects potential network activity of ScreenConnect RMM tool
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
            - 'control.connectwise.com'
            - '*.connectwise.com'
            - '*.screenconnect.com'
    condition: selection
falsepositives:
    - Legitimate use of ScreenConnect
level: medium
```
