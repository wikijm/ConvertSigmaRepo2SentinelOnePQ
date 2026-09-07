```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "helpwire.app" or url.address contains "get.helpwire.app" or url.address contains "api.helpwire.app" or url.address contains "staging.helpwire.app" or url.address contains "account.flexihub.com" or url.address contains "stun.helpwire.app" or url.address contains "stunserver.stunprotocol.org") or (event.dns.request contains "helpwire.app" or event.dns.request contains "get.helpwire.app" or event.dns.request contains "api.helpwire.app" or event.dns.request contains "staging.helpwire.app" or event.dns.request contains "account.flexihub.com" or event.dns.request contains "stun.helpwire.app" or event.dns.request contains "stunserver.stunprotocol.org")))
```


# Original Sigma Rule:
```yaml
title: Potential HelpWire RMM Tool Network Activity
id: 825d9be6-fbf9-511e-a9ab-0ead41cc18ff
status: experimental
description: |
    Detects potential network activity of HelpWire RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-06-11
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
            - 'helpwire.app'
            - 'get.helpwire.app'
            - 'api.helpwire.app'
            - 'staging.helpwire.app'
            - 'account.flexihub.com'
            - 'stun.helpwire.app'
            - 'stunserver.stunprotocol.org'
    condition: selection
falsepositives:
    - Legitimate use of HelpWire
level: medium
```
