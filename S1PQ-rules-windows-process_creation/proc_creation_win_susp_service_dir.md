```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\Users\\Public\\" or tgt.process.image.path contains "\\$Recycle.bin" or tgt.process.image.path contains "\\Users\\All Users\\" or tgt.process.image.path contains "\\Users\\Default\\" or tgt.process.image.path contains "\\Users\\Contacts\\" or tgt.process.image.path contains "\\Users\\Searches\\" or tgt.process.image.path contains "C:\\Perflogs\\" or tgt.process.image.path contains "\\config\\systemprofile\\" or tgt.process.image.path contains "\\Windows\\Fonts\\" or tgt.process.image.path contains "\\Windows\\IME\\" or tgt.process.image.path contains "\\Windows\\addins\\") and (src.process.image.path contains "\\services.exe" or src.process.image.path contains "\\svchost.exe")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Service Binary Directory
id: 883faa95-175a-4e22-8181-e5761aeb373c
status: test
description: Detects a service binary running in a suspicious directory
references:
    - https://blog.truesec.com/2021/03/07/exchange-zero-day-proxylogon-and-hafnium/
author: Florian Roth (Nextron Systems)
date: 2021-03-09
modified: 2022-10-09
tags:
    - attack.defense-evasion
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            - '\Users\Public\'
            - '\$Recycle.bin'
            - '\Users\All Users\'
            - '\Users\Default\'
            - '\Users\Contacts\'
            - '\Users\Searches\'
            - 'C:\Perflogs\'
            - '\config\systemprofile\'
            - '\Windows\Fonts\'
            - '\Windows\IME\'
            - '\Windows\addins\'
        ParentImage|endswith:
            - '\services.exe'
            - '\svchost.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
