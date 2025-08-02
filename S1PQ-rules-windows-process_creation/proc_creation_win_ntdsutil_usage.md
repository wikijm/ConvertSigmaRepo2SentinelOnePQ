```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.image.path contains "\ntdsutil.exe")
```


# Original Sigma Rule:
```yaml
title: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)
id: 2afafd61-6aae-4df4-baed-139fa1f4c345
status: test
description: Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm
author: Thomas Patzke
date: 2019-01-16
modified: 2022-03-11
tags:
    - attack.credential-access
    - attack.t1003.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\ntdsutil.exe'
    condition: selection
falsepositives:
    - NTDS maintenance
level: medium
```
