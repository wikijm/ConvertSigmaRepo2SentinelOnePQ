```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path="C:\WINDOWS\system32\wbem\scrcons.exe" and src.process.image.path="C:\Windows\System32\svchost.exe"))
```


# Original Sigma Rule:
```yaml
title: WMI Persistence - Script Event Consumer
id: ec1d5e28-8f3b-4188-a6f8-6e8df81dc28e
status: test
description: Detects WMI script event consumers
references:
    - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
author: Thomas Patzke
date: 2018-03-07
modified: 2022-10-11
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1546.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: C:\WINDOWS\system32\wbem\scrcons.exe
        ParentImage: C:\Windows\System32\svchost.exe
    condition: selection
falsepositives:
    - Legitimate event consumers
    - Dell computers on some versions register an event consumer that is known to cause false positives when brightness is changed by the corresponding keyboard button
level: medium
```
