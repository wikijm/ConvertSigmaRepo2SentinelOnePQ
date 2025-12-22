```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "guacamole.apache.org") or (event.dns.request contains "user_managed" or event.dns.request contains "guacamole.apache.org")))
```


# Original Sigma Rule:
```yaml
title: Potential Guacamole RMM Tool Network Activity
id: 78a9a1c5-618c-4909-ad62-1ee4b902cc8d
status: experimental
description: |
    Detects potential network activity of Guacamole RMM tool
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
            - guacamole.apache.org
    condition: selection
falsepositives:
    - Legitimate use of Guacamole
level: medium
```
