```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "acceo.com/turbomeeting/") or (event.dns.request contains "user_managed" or event.dns.request contains "acceo.com/turbomeeting/")))
```


# Original Sigma Rule:
```yaml
title: Potential TurboMeeting RMM Tool Network Activity
id: 9e471730-85a2-4a31-8315-a446863da409
status: experimental
description: |
    Detects potential network activity of TurboMeeting RMM tool
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
        DestinationHostname|endswith:
            - user_managed
            - acceo.com/turbomeeting/
    condition: selection
falsepositives:
    - Legitimate use of TurboMeeting
level: medium
```
