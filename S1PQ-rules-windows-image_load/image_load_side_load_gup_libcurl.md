```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and ((src.process.image.path contains "\\gup.exe" and module.path contains "\\libcurl.dll") and (not src.process.image.path contains "\\Notepad++\\updater\\GUP.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential DLL Sideloading Of Libcurl.DLL Via GUP.EXE
id: e49b5745-1064-4ac1-9a2e-f687bc2dd37e
status: test
description: Detects potential DLL sideloading of "libcurl.dll" by the "gup.exe" process from an uncommon location
references:
    - https://labs.withsecure.com/publications/fin7-target-veeam-servers
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-05
tags:
    - attack.defense-evasion
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\gup.exe'
        ImageLoaded|endswith: '\libcurl.dll'
    filter_main_notepad_plusplus:
        Image|endswith: '\Notepad++\updater\GUP.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
