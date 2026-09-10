```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".support.services.microsoft.com" or event.dns.request contains ".support.services.microsoft.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Quick Assist RMM Tool Network Activity
id: 6203a300-6eb8-4263-923e-8d4720702d58
status: experimental
description: |
    Detects potential network activity of Quick Assist RMM tool
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
        DestinationHostname|endswith: '*.support.services.microsoft.com'
    condition: selection
falsepositives:
    - Legitimate use of Quick Assist
level: medium
```
