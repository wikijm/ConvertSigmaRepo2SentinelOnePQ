```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".content.rview.com" or url.address contains ".rview.com" or url.address contains "content.rview.com") or (event.dns.request contains ".content.rview.com" or event.dns.request contains ".rview.com" or event.dns.request contains "content.rview.com")))
```


# Original Sigma Rule:
```yaml
title: Potential RemoteView RMM Tool Network Activity
id: 7159c8eb-d7b8-4802-a204-19b6c1983f38
status: experimental
description: |
    Detects potential network activity of RemoteView RMM tool
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
            - '*.content.rview.com'
            - '*.rview.com'
            - 'content.rview.com'
    condition: selection
falsepositives:
    - Legitimate use of RemoteView
level: medium
```
