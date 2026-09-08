```sql
// Translated content (automatically translated on 08-09-2026 02:55:35):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\offreg.dll" and (not ((src.process.image.path contains "C:\\Windows\\System32\\" or src.process.image.path contains "C:\\Windows\\SysWOW64\\" or src.process.image.path contains "C:\\Windows\\WinSxS\\") or (src.process.image.path contains "C:\\Program Files\\" or src.process.image.path contains "C:\\Program Files (x86)\\") or (src.process.image.path contains "C:\\Users\\" and src.process.image.path contains "\\AppData\\Local\\Programs\\") or (src.process.image.path contains "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\" and src.process.image.path contains "\\MsMpEng.exe")))))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious Image Load of Offreg.dll
id: c9e5f013-4a6f-4d8c-9b0e-f7a4c3d26e95
status: experimental
description: |
    Detects potentially suspicious loading of the Offline Registry Library (offreg.dll).
    Offreg.dll enables direct read/write access to offline registry hives without invoking the Windows Registry API,
    bypassing its associated audit logging and telemetry. Attackers may abuse this to stealthily modify registry hives
    while evading detection mechanisms that rely on standard registry event logs.
references:
    - https://learn.microsoft.com/en-us/windows/win32/devnotes/about-the-offline-registry-library
    - https://github.com/MSNightmare/LegacyHive
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2026-07-23
tags:
    - attack.defense-impairment
    - attack.persistence
    - attack.t1112
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\offreg.dll'
    filter_main_system32:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Windows\WinSxS\'
    filter_main_program_files:
        Image|startswith:
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    filter_main_appdata_local_programs:
        Image|startswith: 'C:\Users\'
        Image|contains: '\AppData\Local\Programs\'
    filter_main_defender:
        Image|startswith: 'C:\ProgramData\Microsoft\Windows Defender\Platform\'
        Image|endswith: '\MsMpEng.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Third-party backup or forensic software that performs offline registry parsing
    - Windows deployment tools (DISM, ADK) run from non-standard paths
level: medium
regression_tests_path: regression_data/rules/windows/image_load/image_load_susp_offreg_dll_load/info.yml
```
