```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\tttracer.exe")
```


# Original Sigma Rule:
```yaml
title: Time Travel Debugging Utility Usage
id: 0b4ae027-2a2d-4b93-8c7e-962caaba5b2a
related:
    - id: e76c8240-d68f-4773-8880-5c6f63595aaf
      type: derived
status: test
description: Detects usage of Time Travel Debugging Utility. Adversaries can execute malicious processes and dump processes, such as lsass.exe, via tttracer.exe.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Tttracer/
    - https://twitter.com/mattifestation/status/1196390321783025666
    - https://twitter.com/oulusoyum/status/1191329746069655553
author: 'Ensar Şamil, @sblmsrsn, @oscd_initiative'
date: 2020-10-06
modified: 2022-10-09
tags:
    - attack.defense-evasion
    - attack.credential-access
    - attack.t1218
    - attack.t1003.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\tttracer.exe'
    condition: selection
falsepositives:
    - Legitimate usage by software developers/testers
level: high
```
