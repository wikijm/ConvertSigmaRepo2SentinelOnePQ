```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/update-ca-certificates" or tgt.process.image.path contains "/update-ca-trust"))
```


# Original Sigma Rule:
```yaml
title: Install Root Certificate
id: 78a80655-a51e-4669-bc6b-e9d206a462ee
status: test
description: Detects installation of new certificate on the system which attackers may use to avoid warnings when connecting to controlled web servers or C2s
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1553.004/T1553.004.md
author: Ömer Günal, oscd.community
date: 2020-10-05
modified: 2022-07-07
tags:
    - attack.defense-evasion
    - attack.t1553.004
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/update-ca-certificates'
            - '/update-ca-trust'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: low
```
