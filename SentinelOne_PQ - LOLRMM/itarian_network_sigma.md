```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "mdmsupport.comodo.com" or url.address contains ".itsm-us1.comodo.com" or url.address contains ".cmdm.comodo.com" or url.address contains "remoteaccess.itarian.com" or url.address contains "servicedesk.itarian.com") or (event.dns.request contains "mdmsupport.comodo.com" or event.dns.request contains ".itsm-us1.comodo.com" or event.dns.request contains ".cmdm.comodo.com" or event.dns.request contains "remoteaccess.itarian.com" or event.dns.request contains "servicedesk.itarian.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Itarian RMM Tool Network Activity
id: 88046776-bd77-44e9-bd62-96501867b81c
status: experimental
description: |
    Detects potential network activity of Itarian RMM tool
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
            - 'mdmsupport.comodo.com'
            - '*.itsm-us1.comodo.com'
            - '*.cmdm.comodo.com'
            - 'remoteaccess.itarian.com'
            - 'servicedesk.itarian.com'
    condition: selection
falsepositives:
    - Legitimate use of Itarian
level: medium
```
