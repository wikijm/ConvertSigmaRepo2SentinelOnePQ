```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and (src.process.image.path contains "\\coregen.exe" and (not (module.path contains "C:\\Program Files (x86)\\Microsoft Silverlight\\" or module.path contains "C:\\Program Files\\Microsoft Silverlight\\" or module.path contains "C:\\Windows\\System32\\" or module.path contains "C:\\Windows\\SysWOW64\\"))))
```


# Original Sigma Rule:
```yaml
title: Potential DLL Sideloading Using Coregen.exe
id: 0fa66f66-e3f6-4a9c-93f8-4f2610b00171
status: test
description: Detect usage of the "coregen.exe" (Microsoft CoreCLR Native Image Generator) binary to sideload arbitrary DLLs.
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Coregen/
author: frack113
date: 2022-12-31
tags:
    - attack.privilege-escalation
    - attack.defense-evasion
    - attack.t1218
    - attack.t1055
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\coregen.exe'
    filter_main_legit_paths:
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\Microsoft Silverlight\'
            - 'C:\Program Files\Microsoft Silverlight\'
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
