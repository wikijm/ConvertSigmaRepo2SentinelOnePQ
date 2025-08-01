```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\dns.exe" and (not tgt.process.image.path contains "\conhost.exe")))
```


# Original Sigma Rule:
```yaml
title: Unusual Child Process of dns.exe
id: a4e3d776-f12e-42c2-8510-9e6ed1f43ec3
status: test
description: Detects an unexpected process spawning from dns.exe which may indicate activity related to remote code execution or other forms of exploitation as seen in CVE-2020-1350 (SigRed)
references:
    - https://www.elastic.co/guide/en/security/current/unusual-child-process-of-dns-exe.html
author: Tim Rauch, Elastic (idea)
date: 2022-09-27
modified: 2023-02-05
tags:
    - attack.initial-access
    - attack.t1133
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\dns.exe'
    filter:
        Image|endswith: '\conhost.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
