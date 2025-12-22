```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and ((src.process.image.path contains "\\arubanetsvc.exe" and (module.path contains "\\wtsapi32.dll" or module.path contains "\\msvcr100.dll" or module.path contains "\\msvcp100.dll" or module.path contains "\\dbghelp.dll" or module.path contains "\\dbgcore.dll" or module.path contains "\\wininet.dll" or module.path contains "\\iphlpapi.dll" or module.path contains "\\version.dll" or module.path contains "\\cryptsp.dll" or module.path contains "\\cryptbase.dll" or module.path contains "\\wldp.dll" or module.path contains "\\profapi.dll" or module.path contains "\\sspicli.dll" or module.path contains "\\winsta.dll" or module.path contains "\\dpapi.dll")) and (not (module.path contains "C:\\Windows\\System32\\" or module.path contains "C:\\Windows\\SysWOW64\\" or module.path contains "C:\\Windows\\WinSxS\\"))))
```


# Original Sigma Rule:
```yaml
title: Aruba Network Service Potential DLL Sideloading
id: 90ae0469-0cee-4509-b67f-e5efcef040f7
status: test
description: Detects potential DLL sideloading activity via the Aruba Networks Virtual Intranet Access "arubanetsvc.exe" process using DLL Search Order Hijacking
references:
    - https://twitter.com/wdormann/status/1616581559892545537?t=XLCBO9BziGzD7Bmbt8oMEQ&s=09
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-22
modified: 2023-03-15
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\arubanetsvc.exe'
        ImageLoaded|endswith:
            - '\wtsapi32.dll'
            - '\msvcr100.dll'
            - '\msvcp100.dll'
            - '\dbghelp.dll'
            - '\dbgcore.dll'
            - '\wininet.dll'
            - '\iphlpapi.dll'
            - '\version.dll'
            - '\cryptsp.dll'
            - '\cryptbase.dll'
            - '\wldp.dll'
            - '\profapi.dll'
            - '\sspicli.dll'
            - '\winsta.dll'
            - '\dpapi.dll'
    filter:
        ImageLoaded|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Windows\WinSxS\'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
