```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "user_managed" or event.dns.request contains "user_managed"))
```


# Original Sigma Rule:
```yaml
title: Potential ESET Remote Administrator RMM Tool Network Activity
id: 1f07c61b-b329-4814-af2a-de7c4bf3e993
status: experimental
description: |
    Detects potential network activity of ESET Remote Administrator RMM tool
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
    - Legitimate use of ESET Remote Administrator
level: medium
```
