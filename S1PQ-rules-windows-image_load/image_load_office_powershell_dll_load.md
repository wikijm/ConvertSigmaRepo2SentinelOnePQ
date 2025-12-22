```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and ((src.process.image.path contains "\\excel.exe" or src.process.image.path contains "\\mspub.exe" or src.process.image.path contains "\\outlook.exe" or src.process.image.path contains "\\onenote.exe" or src.process.image.path contains "\\onenoteim.exe" or src.process.image.path contains "\\powerpnt.exe" or src.process.image.path contains "\\winword.exe") and (module.path contains "\\System.Management.Automation.Dll" or module.path contains "\\System.Management.Automation.ni.Dll")))
```


# Original Sigma Rule:
```yaml
title: PowerShell Core DLL Loaded Via Office Application
id: bb2ba6fb-95d4-4a25-89fc-30bb736c021a
status: test
description: Detects PowerShell core DLL being loaded by an Office Product
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-06-01
tags:
    - attack.defense-evasion
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith:
            - '\excel.exe'
            - '\mspub.exe'
            - '\outlook.exe'
            - '\onenote.exe'
            - '\onenoteim.exe' # Just in case
            - '\powerpnt.exe'
            - '\winword.exe'
        ImageLoaded|contains:
            - '\System.Management.Automation.Dll'
            - '\System.Management.Automation.ni.Dll'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
