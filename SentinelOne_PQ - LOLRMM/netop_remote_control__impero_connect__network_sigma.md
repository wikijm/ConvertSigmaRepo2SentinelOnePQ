```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".connect.backdrop.cloud" or url.address contains ".netop.com") or (event.dns.request contains ".connect.backdrop.cloud" or event.dns.request contains ".netop.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Netop Remote Control (Impero Connect) RMM Tool Network Activity
id: 42ac0f05-030b-4df0-b818-6980374579ab
status: experimental
description: |
    Detects potential network activity of Netop Remote Control (Impero Connect) RMM tool
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
            - '*.connect.backdrop.cloud'
            - '*.netop.com'
    condition: selection
falsepositives:
    - Legitimate use of Netop Remote Control (Impero Connect)
level: medium
```
