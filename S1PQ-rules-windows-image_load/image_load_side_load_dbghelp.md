```sql
// Translated content (automatically translated on 26-09-2025 01:12:35):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\dbghelp.dll" and (not (module.path contains "C:\\Program Files (x86)\\" or module.path contains "C:\\Program Files\\" or module.path contains "C:\\Windows\\SoftwareDistribution\\" or module.path contains "C:\\Windows\\System32\\" or module.path contains "C:\\Windows\\SystemTemp\\" or module.path contains "C:\\Windows\\SysWOW64\\" or module.path contains "C:\\Windows\\WinSxS\\")) and (not ((module.path contains "\\Anaconda3\\Lib\\site-packages\\vtrace\\platforms\\windll\\amd64\\dbghelp.dll" or module.path contains "\\Anaconda3\\Lib\\site-packages\\vtrace\\platforms\\windll\\i386\\dbghelp.dll") or (module.path contains "\\Epic Games\\Launcher\\Engine\\Binaries\\ThirdParty\\DbgHelp\\dbghelp.dll" or module.path contains "\\Epic Games\\MagicLegends\\x86\\dbghelp.dll")))))
```


# Original Sigma Rule:
```yaml
title: Potential DLL Sideloading Of DBGHELP.DLL
id: 6414b5cd-b19d-447e-bb5e-9f03940b5784
status: test
description: Detects potential DLL sideloading of "dbghelp.dll"
references:
    - https://hijacklibs.net/ # For list of DLLs that could be sideloaded (search for dlls mentioned here in there)
author: Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research)
date: 2022-10-25
modified: 2023-05-05
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
        ImageLoaded|endswith: '\dbghelp.dll'
    filter_main_generic:
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\'
            - 'C:\Program Files\'
            - 'C:\Windows\SoftwareDistribution\'
            - 'C:\Windows\System32\'
            - 'C:\Windows\SystemTemp\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Windows\WinSxS\'
    filter_optional_anaconda:
        ImageLoaded|endswith:
            - '\Anaconda3\Lib\site-packages\vtrace\platforms\windll\amd64\dbghelp.dll'
            - '\Anaconda3\Lib\site-packages\vtrace\platforms\windll\i386\dbghelp.dll'
    filter_optional_epicgames:
        ImageLoaded|endswith:
            - '\Epic Games\Launcher\Engine\Binaries\ThirdParty\DbgHelp\dbghelp.dll'
            - '\Epic Games\MagicLegends\x86\dbghelp.dll'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Legitimate applications loading their own versions of the DLL mentioned in this rule
level: medium
```
