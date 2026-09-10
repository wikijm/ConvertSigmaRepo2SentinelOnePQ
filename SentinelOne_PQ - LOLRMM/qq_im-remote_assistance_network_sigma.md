```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".mdt.qq.com" or url.address contains ".desktop.qq.com" or url.address contains "upload_data.qq.com" or url.address contains "qq-messenger.en.softonic.com") or (event.dns.request contains ".mdt.qq.com" or event.dns.request contains ".desktop.qq.com" or event.dns.request contains "upload_data.qq.com" or event.dns.request contains "qq-messenger.en.softonic.com")))
```


# Original Sigma Rule:
```yaml
title: Potential QQ IM-remote assistance RMM Tool Network Activity
id: f146fa65-ccd8-44e5-b3b0-d2250b042f1e
status: experimental
description: |
    Detects potential network activity of QQ IM-remote assistance RMM tool
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
            - '*.mdt.qq.com'
            - '*.desktop.qq.com'
            - 'upload_data.qq.com'
            - 'qq-messenger.en.softonic.com'
    condition: selection
falsepositives:
    - Legitimate use of QQ IM-remote assistance
level: medium
```
