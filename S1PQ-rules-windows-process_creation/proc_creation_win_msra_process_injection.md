```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\msra.exe" and src.process.cmdline contains "msra.exe" and (tgt.process.image.path contains "\\arp.exe" or tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\net.exe" or tgt.process.image.path contains "\\netstat.exe" or tgt.process.image.path contains "\\nslookup.exe" or tgt.process.image.path contains "\\route.exe" or tgt.process.image.path contains "\\schtasks.exe" or tgt.process.image.path contains "\\whoami.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Process Injection Via Msra.EXE
id: 744a188b-0415-4792-896f-11ddb0588dbc
status: test
description: Detects potential process injection via Microsoft Remote Asssistance (Msra.exe) by looking at suspicious child processes spawned from the aforementioned process. It has been a target used by many threat actors and used for discovery and persistence tactics
references:
    - https://www.microsoft.com/security/blog/2021/12/09/a-closer-look-at-qakbots-latest-building-blocks-and-how-to-knock-them-down/
    - https://www.fortinet.com/content/dam/fortinet/assets/analyst-reports/ar-qakbot.pdf
author: Alexander McDonald
date: 2022-06-24
modified: 2023-02-03
tags:
    - attack.privilege-escalation
    - attack.defense-evasion
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\msra.exe'
        ParentCommandLine|endswith: 'msra.exe'
        Image|endswith:
            - '\arp.exe'
            - '\cmd.exe'
            - '\net.exe'
            - '\netstat.exe'
            - '\nslookup.exe'
            - '\route.exe'
            - '\schtasks.exe'
            - '\whoami.exe'
    condition: selection
falsepositives:
    - Legitimate use of Msra.exe
level: high
```
