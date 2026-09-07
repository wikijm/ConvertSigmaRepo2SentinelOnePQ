```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains ".support.services.microsoft.com") or (event.dns.request contains "user_managed" or event.dns.request contains ".support.services.microsoft.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Microsoft Quick Assist RMM Tool Network Activity
id: c6c92332-f901-4f45-a739-abc59797025f
status: experimental
description: |
    Detects potential network activity of Microsoft Quick Assist RMM tool
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
            - 'user_managed'
            - '*.support.services.microsoft.com'
    condition: selection
falsepositives:
    - Legitimate use of Microsoft Quick Assist
level: medium
```
