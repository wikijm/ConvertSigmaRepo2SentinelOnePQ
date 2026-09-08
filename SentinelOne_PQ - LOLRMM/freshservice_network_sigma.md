```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "fstools.freshservice.com" or url.address contains ".freshservice.com" or url.address contains "freshservice.com" or url.address contains "www.freshservice.com" or url.address contains "fstools.freshasset.com" or url.address contains "freshasset.com" or url.address contains ".myfreshworks.com" or url.address contains ".freshworksapi.com" or url.address contains ".freshworks.com" or url.address contains ".freshconnect.io" or url.address contains "api.fdcollab.com" or url.address contains ".fdcollab.com" or url.address contains ".freshchat.com" or url.address contains ".webpush.freshchat.com" or url.address contains "apicdn-wchat.freshchat.com" or url.address contains ".rtschannel.com" or url.address contains ".freshdev.io" or url.address contains "static.freshdev.io" or url.address contains ".freshcloud.io" or url.address contains ".in-freshbots.ai" or url.address contains "<internal-customer-ranges>") or (event.dns.request contains "fstools.freshservice.com" or event.dns.request contains ".freshservice.com" or event.dns.request contains "freshservice.com" or event.dns.request contains "www.freshservice.com" or event.dns.request contains "fstools.freshasset.com" or event.dns.request contains "freshasset.com" or event.dns.request contains ".myfreshworks.com" or event.dns.request contains ".freshworksapi.com" or event.dns.request contains ".freshworks.com" or event.dns.request contains ".freshconnect.io" or event.dns.request contains "api.fdcollab.com" or event.dns.request contains ".fdcollab.com" or event.dns.request contains ".freshchat.com" or event.dns.request contains ".webpush.freshchat.com" or event.dns.request contains "apicdn-wchat.freshchat.com" or event.dns.request contains ".rtschannel.com" or event.dns.request contains ".freshdev.io" or event.dns.request contains "static.freshdev.io" or event.dns.request contains ".freshcloud.io" or event.dns.request contains ".in-freshbots.ai" or event.dns.request contains "<internal-customer-ranges>")))
```


# Original Sigma Rule:
```yaml
title: Potential Freshservice RMM Tool Network Activity
id: 759d870d-2a70-59bd-875c-ff1dfb85574a
status: experimental
description: |
    Detects potential network activity of Freshservice RMM tool
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
            - 'fstools.freshservice.com'
            - '*.freshservice.com'
            - 'freshservice.com'
            - 'www.freshservice.com'
            - 'fstools.freshasset.com'
            - 'freshasset.com'
            - '*.myfreshworks.com'
            - '*.freshworksapi.com'
            - '*.freshworks.com'
            - '*.freshconnect.io'
            - 'api.fdcollab.com'
            - '*.fdcollab.com'
            - '*.freshchat.com'
            - '*.webpush.freshchat.com'
            - 'apicdn-wchat.freshchat.com'
            - '*.rtschannel.com'
            - '*.freshdev.io'
            - 'static.freshdev.io'
            - '*.freshcloud.io'
            - '*.in-freshbots.ai'
            - '<internal-customer-ranges>'
    condition: selection
falsepositives:
    - Legitimate use of Freshservice
level: medium
```
