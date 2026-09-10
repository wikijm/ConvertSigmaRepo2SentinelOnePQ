```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".itsupport247.net" or url.address contains "itsupport247.net") or (event.dns.request contains ".itsupport247.net" or event.dns.request contains "itsupport247.net")))
```


# Original Sigma Rule:
```yaml
title: Potential ITSupport247 (ConnectWise) RMM Tool Network Activity
id: 2966b368-1e5b-4abb-9cde-30a84e747b6f
status: experimental
description: |
    Detects potential network activity of ITSupport247 (ConnectWise) RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-09-09
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - '*.itsupport247.net'
            - 'itsupport247.net'
    condition: selection
falsepositives:
    - Legitimate use of ITSupport247 (ConnectWise)
level: medium
```
