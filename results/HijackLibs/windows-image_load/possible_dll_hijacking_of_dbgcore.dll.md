```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\dbgcore.dll" and (not (module.path="c:\program files\windows kits\10\debuggers\arm\*" or module.path="c:\program files (x86)\windows kits\10\debuggers\arm\*" or module.path="c:\program files\windows kits\10\debuggers\arm\srcsrv\*" or module.path="c:\program files (x86)\windows kits\10\debuggers\arm\srcsrv\*" or module.path="c:\program files\windows kits\10\debuggers\arm64\*" or module.path="c:\program files (x86)\windows kits\10\debuggers\arm64\*" or module.path="c:\program files\windows kits\10\debuggers\arm64\srcsrv\*" or module.path="c:\program files (x86)\windows kits\10\debuggers\arm64\srcsrv\*" or module.path="c:\program files\windows kits\10\debuggers\x64\*" or module.path="c:\program files (x86)\windows kits\10\debuggers\x64\*" or module.path="c:\program files\windows kits\10\debuggers\x64\srcsrv\*" or module.path="c:\program files (x86)\windows kits\10\debuggers\x64\srcsrv\*" or module.path="c:\program files\windows kits\10\debuggers\x86\*" or module.path="c:\program files (x86)\windows kits\10\debuggers\x86\*" or module.path="c:\program files\windows kits\10\debuggers\x86\srcsrv\*" or module.path="c:\program files (x86)\windows kits\10\debuggers\x86\srcsrv\*" or module.path="c:\program files\microsoft office\root\office*\*" or module.path="c:\program files (x86)\microsoft office\root\office*\*" or module.path="c:\windows\system32\*" or module.path="c:\windows\syswow64\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of dbgcore.dll
id: 3986661b-9395-48a3-4833-5b9ff8671231
status: experimental
description: Detects possible DLL hijacking of dbgcore.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/dbgcore.html
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
        ImageLoaded: '*\dbgcore.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\windows kits\10\debuggers\arm\*'
            - 'c:\program files (x86)\windows kits\10\debuggers\arm\*'
            - 'c:\program files\windows kits\10\debuggers\arm\srcsrv\*'
            - 'c:\program files (x86)\windows kits\10\debuggers\arm\srcsrv\*'
            - 'c:\program files\windows kits\10\debuggers\arm64\*'
            - 'c:\program files (x86)\windows kits\10\debuggers\arm64\*'
            - 'c:\program files\windows kits\10\debuggers\arm64\srcsrv\*'
            - 'c:\program files (x86)\windows kits\10\debuggers\arm64\srcsrv\*'
            - 'c:\program files\windows kits\10\debuggers\x64\*'
            - 'c:\program files (x86)\windows kits\10\debuggers\x64\*'
            - 'c:\program files\windows kits\10\debuggers\x64\srcsrv\*'
            - 'c:\program files (x86)\windows kits\10\debuggers\x64\srcsrv\*'
            - 'c:\program files\windows kits\10\debuggers\x86\*'
            - 'c:\program files (x86)\windows kits\10\debuggers\x86\*'
            - 'c:\program files\windows kits\10\debuggers\x86\srcsrv\*'
            - 'c:\program files (x86)\windows kits\10\debuggers\x86\srcsrv\*'
            - 'c:\program files\microsoft office\root\office*\*'
            - 'c:\program files (x86)\microsoft office\root\office*\*'
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
