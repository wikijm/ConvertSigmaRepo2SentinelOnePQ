```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\iodine.exe" or tgt.process.image.path contains "\\dnscat2"))
```


# Original Sigma Rule:
```yaml
title: DNS Exfiltration and Tunneling Tools Execution
id: 98a96a5a-64a0-4c42-92c5-489da3866cb0
status: test
description: Well-known DNS Exfiltration tools execution
references:
    - https://github.com/iagox86/dnscat2
    - https://github.com/yarrick/iodine
author: Daniil Yugoslavskiy, oscd.community
date: 2019-10-24
modified: 2021-11-27
tags:
    - attack.exfiltration
    - attack.t1048.001
    - attack.command-and-control
    - attack.t1071.004
    - attack.t1132.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\iodine.exe'
        - Image|contains: '\dnscat2'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
