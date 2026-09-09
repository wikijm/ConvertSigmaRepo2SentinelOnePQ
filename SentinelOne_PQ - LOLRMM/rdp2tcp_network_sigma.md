```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "user_managed" or event.dns.request contains "user_managed"))
```


# Original Sigma Rule:
```yaml
title: Potential rdp2tcp RMM Tool Network Activity
id: 7185a584-cd76-4bc8-bae0-1d6a0a3741a9
status: experimental
description: |
    Detects potential network activity of rdp2tcp RMM tool
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
        DestinationHostname|endswith: 'user_managed'
    condition: selection
falsepositives:
    - Legitimate use of rdp2tcp
level: medium
```
