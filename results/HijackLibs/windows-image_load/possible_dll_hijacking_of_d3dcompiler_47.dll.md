```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\d3dcompiler_47.dll" and (not (module.path in ("c:\program files\windows kits\10\bin\*\x64\*","c:\program files (x86)\windows kits\10\bin\*\x64\*","c:\program files\windows kits\10\bin\*\x86\*","c:\program files (x86)\windows kits\10\bin\*\x86\*","c:\program files\windows kits\10\redist\d3d\x64\*","c:\program files (x86)\windows kits\10\redist\d3d\x64\*","c:\program files\windows kits\10\redist\d3d\x86\*","c:\program files (x86)\windows kits\10\redist\d3d\x86\*","c:\program files\wireshark\*","c:\program files (x86)\wireshark\*","c:\program files\LogiOptionsPlus\*","c:\program files (x86)\LogiOptionsPlus\*","c:\program files\cisco systems\cisco jabber\*","c:\program files (x86)\cisco systems\cisco jabber\*","c:\program files\microsoft\edge\application\*\*","c:\program files (x86)\microsoft\edge\application\*\*","c:\program files\microsoft\edgewebview\application\*\*","c:\program files (x86)\microsoft\edgewebview\application\*\*","c:\program files\microsoft\edgecore\application\*\*","c:\program files (x86)\microsoft\edgecore\application\*\*","c:\program files\Google\Chrome\Application\*\*","c:\program files (x86)\Google\Chrome\Application\*\*","c:\program files\Island\Island\Application\*\*","c:\program files (x86)\Island\Island\Application\*\*","c:\program files\Zoom\bin\*","c:\program files (x86)\Zoom\bin\*","c:\users\*\appdata\roaming\Zoom\bin\*","c:\users\*\appdata\local\microsoft\teams\stage\*","c:\users\*\appdata\local\Programs\Microsoft VS Code\*","c:\windows\system32\*","c:\windows\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of d3dcompiler_47.dll
id: 4206841b-9395-48a3-4833-5b9ff8530571
status: experimental
description: Detects possible DLL hijacking of d3dcompiler_47.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/d3dcompiler_47.html
author: "Wietze Beukema"
date: 2021-02-27
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\d3dcompiler_47.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\windows kits\10\bin\*\x64\*'
            - 'c:\program files (x86)\windows kits\10\bin\*\x64\*'
            - 'c:\program files\windows kits\10\bin\*\x86\*'
            - 'c:\program files (x86)\windows kits\10\bin\*\x86\*'
            - 'c:\program files\windows kits\10\redist\d3d\x64\*'
            - 'c:\program files (x86)\windows kits\10\redist\d3d\x64\*'
            - 'c:\program files\windows kits\10\redist\d3d\x86\*'
            - 'c:\program files (x86)\windows kits\10\redist\d3d\x86\*'
            - 'c:\program files\wireshark\*'
            - 'c:\program files (x86)\wireshark\*'
            - 'c:\program files\LogiOptionsPlus\*'
            - 'c:\program files (x86)\LogiOptionsPlus\*'
            - 'c:\program files\cisco systems\cisco jabber\*'
            - 'c:\program files (x86)\cisco systems\cisco jabber\*'
            - 'c:\program files\microsoft\edge\application\*\*'
            - 'c:\program files (x86)\microsoft\edge\application\*\*'
            - 'c:\program files\microsoft\edgewebview\application\*\*'
            - 'c:\program files (x86)\microsoft\edgewebview\application\*\*'
            - 'c:\program files\microsoft\edgecore\application\*\*'
            - 'c:\program files (x86)\microsoft\edgecore\application\*\*'
            - 'c:\program files\Google\Chrome\Application\*\*'
            - 'c:\program files (x86)\Google\Chrome\Application\*\*'
            - 'c:\program files\Island\Island\Application\*\*'
            - 'c:\program files (x86)\Island\Island\Application\*\*'
            - 'c:\program files\Zoom\bin\*'
            - 'c:\program files (x86)\Zoom\bin\*'
            - 'c:\users\*\appdata\roaming\Zoom\bin\*'
            - 'c:\users\*\appdata\local\microsoft\teams\stage\*'
            - 'c:\users\*\appdata\local\Programs\Microsoft VS Code\*'
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
