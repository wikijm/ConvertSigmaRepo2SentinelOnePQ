```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".zoho.com.au" or url.address contains ".zohoassist.jp" or url.address contains "assist.zoho.com" or url.address contains ".zoho.in" or url.address contains "downloads.zohodl.com.cn" or url.address contains ".zohoassist.com" or url.address contains "downloads.zohocdn.com" or url.address contains "gateway.zohoassist.com" or url.address contains ".zohoassist.com.cn" or url.address contains ".zoho.com.cn" or url.address contains ".zoho.com" or url.address contains ".zoho.eu") or (event.dns.request contains ".zoho.com.au" or event.dns.request contains ".zohoassist.jp" or event.dns.request contains "assist.zoho.com" or event.dns.request contains ".zoho.in" or event.dns.request contains "downloads.zohodl.com.cn" or event.dns.request contains ".zohoassist.com" or event.dns.request contains "downloads.zohocdn.com" or event.dns.request contains "gateway.zohoassist.com" or event.dns.request contains ".zohoassist.com.cn" or event.dns.request contains ".zoho.com.cn" or event.dns.request contains ".zoho.com" or event.dns.request contains ".zoho.eu")))
```


# Original Sigma Rule:
```yaml
title: Potential Zoho Assist RMM Tool Network Activity
id: 3ae241e0-ab8f-4e0a-8d6b-02f6687866cd
status: experimental
description: |
    Detects potential network activity of Zoho Assist RMM tool
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
            - '*.zoho.com.au'
            - '*.zohoassist.jp'
            - 'assist.zoho.com'
            - '*.zoho.in'
            - 'downloads.zohodl.com.cn'
            - '*.zohoassist.com'
            - 'downloads.zohocdn.com'
            - 'gateway.zohoassist.com'
            - '*.zohoassist.com.cn'
            - '*.zoho.com.cn'
            - '*.zoho.com'
            - '*.zoho.eu'
    condition: selection
falsepositives:
    - Legitimate use of Zoho Assist
level: medium
```
