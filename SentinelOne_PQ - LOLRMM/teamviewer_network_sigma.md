```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".teamviewer.com" or url.address contains "router15.teamviewer.com" or url.address contains "client.teamviewer.com" or url.address contains "taf.teamviewer.com") or (event.dns.request contains ".teamviewer.com" or event.dns.request contains "router15.teamviewer.com" or event.dns.request contains "client.teamviewer.com" or event.dns.request contains "taf.teamviewer.com")))
```


# Original Sigma Rule:
```yaml
title: Potential TeamViewer RMM Tool Network Activity
id: dfe972f9-9cae-4e5a-b7a6-faf64a589059
status: experimental
description: |
    Detects potential network activity of TeamViewer RMM tool
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
            - '*.teamviewer.com'
            - 'router15.teamviewer.com'
            - 'client.teamviewer.com'
            - 'taf.teamviewer.com'
    condition: selection
falsepositives:
    - Legitimate use of TeamViewer
level: medium
```
