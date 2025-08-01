```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\Windows\System32\lsass.exe" and tgt.process.image.path contains "\Windows\System32\lsass.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Credential Dumping Via LSASS Process Clone
id: c8da0dfd-4ed0-4b68-962d-13c9c884384e
status: test
description: Detects a suspicious LSASS process process clone that could be a sign of credential dumping activity
references:
    - https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/
    - https://twitter.com/Hexacorn/status/1420053502554951689
    - https://twitter.com/SBousseaden/status/1464566846594691073?s=20
author: Florian Roth (Nextron Systems), Samir Bousseaden
date: 2021-11-27
modified: 2023-03-02
tags:
    - attack.credential-access
    - attack.t1003
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\Windows\System32\lsass.exe'
        Image|endswith: '\Windows\System32\lsass.exe'
    condition: selection
falsepositives:
    - Unknown
level: critical
```
