```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "invgate.com" or url.address contains "www.invgate.com" or url.address contains ".invgate.net" or url.address contains "invgate.net" or url.address contains "lb-insight-001.invgate.net" or url.address contains "trust.invgate.com" or url.address contains "trust-access.invgate.com" or url.address contains "instances-info.invgate.com" or url.address contains "instances-list.invgate.com" or url.address contains "releases.invgate.com" or url.address contains "docs.invgate.net" or url.address contains "help.invgate.com") or (event.dns.request contains "invgate.com" or event.dns.request contains "www.invgate.com" or event.dns.request contains ".invgate.net" or event.dns.request contains "invgate.net" or event.dns.request contains "lb-insight-001.invgate.net" or event.dns.request contains "trust.invgate.com" or event.dns.request contains "trust-access.invgate.com" or event.dns.request contains "instances-info.invgate.com" or event.dns.request contains "instances-list.invgate.com" or event.dns.request contains "releases.invgate.com" or event.dns.request contains "docs.invgate.net" or event.dns.request contains "help.invgate.com")))
```


# Original Sigma Rule:
```yaml
title: Potential InvGate RMM Tool Network Activity
id: ad2f855c-8c85-570a-be35-49110974af92
status: experimental
description: |
    Detects potential network activity of InvGate RMM tool
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
            - 'invgate.com'
            - 'www.invgate.com'
            - '*.invgate.net'
            - 'invgate.net'
            - 'lb-insight-001.invgate.net'
            - 'trust.invgate.com'
            - 'trust-access.invgate.com'
            - 'instances-info.invgate.com'
            - 'instances-list.invgate.com'
            - 'releases.invgate.com'
            - 'docs.invgate.net'
            - 'help.invgate.com'
    condition: selection
falsepositives:
    - Legitimate use of InvGate
level: medium
```
