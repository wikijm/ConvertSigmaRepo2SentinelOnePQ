```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".manageengine.com" or url.address contains "manageengine.com") or (event.dns.request contains ".manageengine.com" or event.dns.request contains "manageengine.com")))
```


# Original Sigma Rule:
```yaml
title: Potential ManageEngine ServiceDesk Plus RMM Tool Network Activity
id: 491304ad-942a-5be3-8678-62efa8c09743
status: experimental
description: |
    Detects potential network activity of ManageEngine ServiceDesk Plus RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
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
            - '*.manageengine.com'
            - 'manageengine.com'
    condition: selection
falsepositives:
    - Legitimate use of ManageEngine ServiceDesk Plus
level: medium
```
