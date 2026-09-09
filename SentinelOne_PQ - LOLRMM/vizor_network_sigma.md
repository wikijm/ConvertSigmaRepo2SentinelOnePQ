```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "<operator-configured Vector Discovery Server URL>" or url.address contains "vizor.cloud" or url.address contains "www.vizor.cloud" or url.address contains "vector-networks.com" or url.address contains "www.vector-networks.com" or url.address contains "metaquest.com" or url.address contains "mail.metaquest.com" or url.address contains "www.metaquest.com" or url.address contains "downloads.vector-networks.com") or (event.dns.request contains "<operator-configured Vector Discovery Server URL>" or event.dns.request contains "vizor.cloud" or event.dns.request contains "www.vizor.cloud" or event.dns.request contains "vector-networks.com" or event.dns.request contains "www.vector-networks.com" or event.dns.request contains "metaquest.com" or event.dns.request contains "mail.metaquest.com" or event.dns.request contains "www.metaquest.com" or event.dns.request contains "downloads.vector-networks.com")))
```


# Original Sigma Rule:
```yaml
title: Potential VIZOR RMM Tool Network Activity
id: 7f21b9c6-6737-5320-a983-09a5e659007b
status: experimental
description: |
    Detects potential network activity of VIZOR RMM tool
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
            - '<operator-configured Vector Discovery Server URL>'
            - 'vizor.cloud'
            - 'www.vizor.cloud'
            - 'vector-networks.com'
            - 'www.vector-networks.com'
            - 'metaquest.com'
            - 'mail.metaquest.com'
            - 'www.metaquest.com'
            - 'downloads.vector-networks.com'
    condition: selection
falsepositives:
    - Legitimate use of VIZOR
level: medium
```
