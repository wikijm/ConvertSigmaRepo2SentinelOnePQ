```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".logmeinrescue.com" or url.address contains ".logmeinrescue.eu" or url.address contains "logmeinrescue.com" or url.address="*rescue-list.*.logmein-gateway.com" or url.address contains "rescue-data-cetner.logmein-gateway.com") or (event.dns.request contains ".logmeinrescue.com" or event.dns.request contains ".logmeinrescue.eu" or event.dns.request contains "logmeinrescue.com" or event.dns.request="*rescue-list.*.logmein-gateway.com" or event.dns.request contains "rescue-data-cetner.logmein-gateway.com")))
```


# Original Sigma Rule:
```yaml
title: Potential LogMeIn rescue RMM Tool Network Activity
id: 4eaa85dd-e3db-4410-bd7f-89c855f69d39
status: experimental
description: |
    Detects potential network activity of LogMeIn rescue RMM tool
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
            - '*.logmeinrescue.com'
            - '*.logmeinrescue.eu'
            - 'logmeinrescue.com'
            - 'rescue-list.*.logmein-gateway.com'
            - 'rescue-data-cetner.logmein-gateway.com'
    condition: selection
falsepositives:
    - Legitimate use of LogMeIn rescue
level: medium
```
