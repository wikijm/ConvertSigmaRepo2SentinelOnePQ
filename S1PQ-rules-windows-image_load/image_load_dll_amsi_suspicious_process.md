```sql
// Translated content (automatically translated on 07-06-2025 01:18:24):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\amsi.dll" and (src.process.image.path contains "\ExtExport.exe" or src.process.image.path contains "\odbcconf.exe" or src.process.image.path contains "\regsvr32.exe" or src.process.image.path contains "\rundll32.exe")))
```


# Original Sigma Rule:
```yaml
title: Amsi.DLL Loaded Via LOLBIN Process
id: 6ec86d9e-912e-4726-91a2-209359b999b9
status: test
description: Detects loading of "Amsi.dll" by a living of the land process. This could be an indication of a "PowerShell without PowerShell" attack
references:
    - Internal Research
    - https://www.paloaltonetworks.com/blog/security-operations/stopping-powershell-without-powershell/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-06-01
modified: 2023-09-20
tags:
    - attack.defense-evasion
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\amsi.dll'
        Image|endswith:
            # TODO: Add more interesting processes
            - '\ExtExport.exe'
            - '\odbcconf.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
