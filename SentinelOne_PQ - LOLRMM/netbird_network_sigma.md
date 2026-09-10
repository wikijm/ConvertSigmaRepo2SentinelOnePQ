```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "netbird.io" or url.address contains ".netbird.io" or url.address contains "api.netbird.io" or url.address contains "app.netbird.io" or url.address contains "signal.netbird.io" or url.address contains "relay.netbird.io" or url.address contains "login.netbird.io" or url.address contains "pkgs.netbird.io" or url.address contains "192.3.95.152" or url.address contains "198.46.178.135" or url.address contains "googl-6c11f.firebaseapp.com" or url.address contains "googl-6c11f.web.app" or url.address contains "googl-165a0.web.app" or url.address contains "cloud-ed980.firebaseapp.com" or url.address contains "cloud-233f9.firebaseapp.com" or url.address contains "my-sharepoint-inc.com" or url.address contains "my1cloudlive.com" or url.address contains "my2cloudlive.com" or url.address contains "web-16fe.app") or (event.dns.request contains "netbird.io" or event.dns.request contains ".netbird.io" or event.dns.request contains "api.netbird.io" or event.dns.request contains "app.netbird.io" or event.dns.request contains "signal.netbird.io" or event.dns.request contains "relay.netbird.io" or event.dns.request contains "login.netbird.io" or event.dns.request contains "pkgs.netbird.io" or event.dns.request contains "192.3.95.152" or event.dns.request contains "198.46.178.135" or event.dns.request contains "googl-6c11f.firebaseapp.com" or event.dns.request contains "googl-6c11f.web.app" or event.dns.request contains "googl-165a0.web.app" or event.dns.request contains "cloud-ed980.firebaseapp.com" or event.dns.request contains "cloud-233f9.firebaseapp.com" or event.dns.request contains "my-sharepoint-inc.com" or event.dns.request contains "my1cloudlive.com" or event.dns.request contains "my2cloudlive.com" or event.dns.request contains "web-16fe.app")))
```


# Original Sigma Rule:
```yaml
title: Potential NetBird RMM Tool Network Activity
id: b185f048-8668-5dba-a8fa-09e8d9fd2097
status: experimental
description: |
    Detects potential network activity of NetBird RMM tool
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
            - 'netbird.io'
            - '*.netbird.io'
            - 'api.netbird.io'
            - 'app.netbird.io'
            - 'signal.netbird.io'
            - 'relay.netbird.io'
            - 'login.netbird.io'
            - 'pkgs.netbird.io'
            - '192.3.95.152'
            - '198.46.178.135'
            - 'googl-6c11f.firebaseapp.com'
            - 'googl-6c11f.web.app'
            - 'googl-165a0.web.app'
            - 'cloud-ed980.firebaseapp.com'
            - 'cloud-233f9.firebaseapp.com'
            - 'my-sharepoint-inc.com'
            - 'my1cloudlive.com'
            - 'my2cloudlive.com'
            - 'web-16fe.app'
    condition: selection
falsepositives:
    - Legitimate use of NetBird
level: medium
```
