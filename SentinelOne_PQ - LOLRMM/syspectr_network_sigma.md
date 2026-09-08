```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".syspectr.com" or url.address contains "syspectr.com") or (event.dns.request contains ".syspectr.com" or event.dns.request contains "syspectr.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Syspectr RMM Tool Network Activity
id: 7f19fc2c-6952-4582-84c7-70d1e19171f9
status: experimental
description: |
    Detects potential network activity of Syspectr RMM tool
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
            - '*.syspectr.com'
            - 'syspectr.com'
    condition: selection
falsepositives:
    - Legitimate use of Syspectr
level: medium
```
