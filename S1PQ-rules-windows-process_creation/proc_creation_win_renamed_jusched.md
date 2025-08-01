```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.displayName in ("Java Update Scheduler","Java(TM) Update Scheduler")) and (not tgt.process.image.path contains "\jusched.exe")))
```


# Original Sigma Rule:
```yaml
title: Renamed Jusched.EXE Execution
id: edd8a48c-1b9f-4ba1-83aa-490338cd1ccb
status: test
description: Detects the execution of a renamed "jusched.exe" as seen used by the cobalt group
references:
    - https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf
author: Markus Neis, Swisscom
date: 2019-06-04
modified: 2023-02-03
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.t1036.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Description:
            - Java Update Scheduler
            - Java(TM) Update Scheduler
    filter:
        Image|endswith: '\jusched.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
