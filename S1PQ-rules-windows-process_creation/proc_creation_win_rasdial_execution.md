```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.image.path contains "rasdial.exe")
```


# Original Sigma Rule:
```yaml
title: Suspicious RASdial Activity
id: 6bba49bf-7f8c-47d6-a1bb-6b4dece4640e
status: test
description: Detects suspicious process related to rasdial.exe
references:
    - https://twitter.com/subTee/status/891298217907830785
author: juju4
date: 2019-01-16
modified: 2021-11-27
tags:
    - attack.defense-evasion
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 'rasdial.exe'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
```
