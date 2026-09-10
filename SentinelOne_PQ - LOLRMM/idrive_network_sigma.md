```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "idrive.com" or url.address contains ".idrive.com" or url.address contains "api.idrive.com") or (event.dns.request contains "idrive.com" or event.dns.request contains ".idrive.com" or event.dns.request contains "api.idrive.com")))
```


# Original Sigma Rule:
```yaml
title: Potential iDrive RMM Tool Network Activity
id: 0a2dacc5-f6e5-57ee-bd53-cbd15c182bf8
status: experimental
description: |
    Detects potential network activity of iDrive RMM tool
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
            - 'idrive.com'
            - '*.idrive.com'
            - 'api.idrive.com'
    condition: selection
falsepositives:
    - Legitimate use of iDrive
level: medium
```
