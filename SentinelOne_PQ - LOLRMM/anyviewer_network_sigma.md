```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".anyviewer.com" or url.address contains ".aomeisoftware.com") or (event.dns.request contains ".anyviewer.com" or event.dns.request contains ".aomeisoftware.com")))
```


# Original Sigma Rule:
```yaml
title: Potential AnyViewer RMM Tool Network Activity
id: f79262ed-7f6b-40f8-ac51-245aecab6b97
status: experimental
description: |
    Detects potential network activity of AnyViewer RMM tool
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
            - '*.anyviewer.com'
            - '*.aomeisoftware.com'
    condition: selection
falsepositives:
    - Legitimate use of AnyViewer
level: medium
```
