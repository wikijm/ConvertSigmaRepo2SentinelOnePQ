```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and ((module.path contains "\libwazuhshared.dll" or module.path contains "\libwinpthread-1.dll") and (not (module.path contains "C:\Program Files\" or module.path contains "C:\Program Files (x86)\")) and (not ((module.path contains "\AppData\Local\" or module.path contains "\ProgramData\") and module.path contains "\mingw64\bin\libwinpthread-1.dll"))))
```


# Original Sigma Rule:
```yaml
title: Potential Wazuh Security Platform DLL Sideloading
id: db77ce78-7e28-4188-9337-cf30e2b3ba9f
status: test
description: Detects potential DLL side loading of DLLs that are part of the Wazuh security platform
references:
    - https://www.trendmicro.com/en_us/research/23/c/iron-tiger-sysupdate-adds-linux-targeting.html
author: X__Junior (Nextron Systems)
date: 2023-03-13
modified: 2023-05-12
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
        ImageLoaded|endswith:
            - '\libwazuhshared.dll'
            - '\libwinpthread-1.dll'
    filter_main_generic:
        ImageLoaded|startswith:
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    filter_optional_mingw64:
        # Note: Many third party apps installed in "AppData" or "ProgramData" and leverage "mingw64" make use of "libwinpthread-1.dll"
        # In production its best to make a list of these apps and replace this filter with a specific one.
        ImageLoaded|contains:
            - '\AppData\Local\'
            - '\ProgramData\'
        ImageLoaded|endswith: '\mingw64\bin\libwinpthread-1.dll'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Many legitimate applications leverage this DLL. (Visual Studio, JetBrains, Ruby, Anaconda, GithubDesktop, etc.)
level: medium
```
