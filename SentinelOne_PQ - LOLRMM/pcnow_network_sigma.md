```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "au.pcmag.com/utilities/21470/webex-pcnow" or event.dns.request contains "au.pcmag.com/utilities/21470/webex-pcnow"))
```


# Original Sigma Rule:
```yaml
title: Potential Pcnow RMM Tool Network Activity
id: cddaeacc-ee3f-416f-96b9-48966475dd25
status: experimental
description: |
    Detects potential network activity of Pcnow RMM tool
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
        DestinationHostname|endswith: au.pcmag.com/utilities/21470/webex-pcnow
    condition: selection
falsepositives:
    - Legitimate use of Pcnow
level: medium
```
