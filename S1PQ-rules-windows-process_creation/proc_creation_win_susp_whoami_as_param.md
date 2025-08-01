```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline contains ".exe whoami")
```


# Original Sigma Rule:
```yaml
title: WhoAmI as Parameter
id: e9142d84-fbe0-401d-ac50-3e519fb00c89
status: test
description: Detects a suspicious process command line that uses whoami as first parameter (as e.g. used by EfsPotato)
references:
    - https://twitter.com/blackarrowsec/status/1463805700602224645?s=12
author: Florian Roth (Nextron Systems)
date: 2021-11-29
modified: 2022-12-25
tags:
    - attack.discovery
    - attack.t1033
    - car.2016-03-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '.exe whoami'
    condition: selection
falsepositives:
    - Unknown
level: high
```
