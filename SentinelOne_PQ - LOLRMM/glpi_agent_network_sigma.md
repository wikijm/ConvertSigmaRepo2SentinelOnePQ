```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "<operator-configured GLPI server>" or url.address contains "glpi-project.org" or url.address contains "www.glpi-project.org" or url.address contains "nightly.glpi-project.org" or url.address contains "forum.glpi-project.org" or url.address contains "glpi-network.com" or url.address contains "services.glpi-network.com" or url.address contains "github.com" or url.address contains "objects.githubusercontent.com") or (event.dns.request contains "<operator-configured GLPI server>" or event.dns.request contains "glpi-project.org" or event.dns.request contains "www.glpi-project.org" or event.dns.request contains "nightly.glpi-project.org" or event.dns.request contains "forum.glpi-project.org" or event.dns.request contains "glpi-network.com" or event.dns.request contains "services.glpi-network.com" or event.dns.request contains "github.com" or event.dns.request contains "objects.githubusercontent.com")))
```


# Original Sigma Rule:
```yaml
title: Potential GLPI Agent RMM Tool Network Activity
id: 47e1cc56-2677-52dc-b1ad-b6d24b617c25
status: experimental
description: |
    Detects potential network activity of GLPI Agent RMM tool
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
            - '<operator-configured GLPI server>'
            - 'glpi-project.org'
            - 'www.glpi-project.org'
            - 'nightly.glpi-project.org'
            - 'forum.glpi-project.org'
            - 'glpi-network.com'
            - 'services.glpi-network.com'
            - 'github.com'
            - 'objects.githubusercontent.com'
    condition: selection
falsepositives:
    - Legitimate use of GLPI Agent
level: medium
```
