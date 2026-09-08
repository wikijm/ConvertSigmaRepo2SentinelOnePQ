```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "user_managed" or event.dns.request contains "user_managed"))
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
    - Legitimate use of TurboMeeting
level: medium
```
