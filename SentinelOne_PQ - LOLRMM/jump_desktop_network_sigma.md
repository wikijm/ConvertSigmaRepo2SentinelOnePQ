```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".jumpdesktop.com" or url.address contains "jumpdesktop.com" or url.address contains "jumpto.me" or url.address contains ".jumpto.me") or (event.dns.request contains ".jumpdesktop.com" or event.dns.request contains "jumpdesktop.com" or event.dns.request contains "jumpto.me" or event.dns.request contains ".jumpto.me")))
```


# Original Sigma Rule:
```yaml
title: Potential Jump Desktop RMM Tool Network Activity
id: dece7c90-f789-4724-a787-e65445e232b2
status: experimental
description: |
    Detects potential network activity of Jump Desktop RMM tool
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
            - '*.jumpdesktop.com'
            - 'jumpdesktop.com'
            - 'jumpto.me'
            - '*.jumpto.me'
    condition: selection
falsepositives:
    - Legitimate use of Jump Desktop
level: medium
```
