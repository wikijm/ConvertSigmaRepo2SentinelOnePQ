```sql
// Translated content (automatically translated on 10-09-2026 03:38:18):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\nethost.dll" and (not (module.path="c:\\program files\\dotnet\\packs\\Microsoft.NETCore.App.Host.win-x64\\*\\runtimes\\win-x64\\native\\*" or module.path="c:\\program files (x86)\\dotnet\\packs\\Microsoft.NETCore.App.Host.win-x64\\*\\runtimes\\win-x64\\native\\*" or module.path="c:\\program files\\dotnet\\packs\\Microsoft.NETCore.App.Host.win-x86\\*\\runtimes\\win-x86\\native\\*" or module.path="c:\\program files (x86)\\dotnet\\packs\\Microsoft.NETCore.App.Host.win-x86\\*\\runtimes\\win-x86\\native\\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of nethost.dll
id: 2114601b-2217-48a3-2635-5b9ff8907340
status: experimental
description: Detects possible DLL hijacking of nethost.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/nethost.html
author: "Josh Allman"
date: 2026-04-19
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\nethost.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\dotnet\packs\Microsoft.NETCore.App.Host.win-x64\\*\runtimes\win-x64\native\\*'
            - 'c:\program files (x86)\dotnet\packs\Microsoft.NETCore.App.Host.win-x64\\*\runtimes\win-x64\native\\*'
            - 'c:\program files\dotnet\packs\Microsoft.NETCore.App.Host.win-x86\\*\runtimes\win-x86\native\\*'
            - 'c:\program files (x86)\dotnet\packs\Microsoft.NETCore.App.Host.win-x86\\*\runtimes\win-x86\native\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
