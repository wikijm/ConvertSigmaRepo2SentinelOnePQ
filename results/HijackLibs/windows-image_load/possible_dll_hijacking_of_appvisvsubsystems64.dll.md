```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\appvisvsubsystems64.dll" and (not (module.path="c:\\program files\\Common Files\\microsoft shared\\ClickToRun\*" or module.path="c:\\program files (x86)\\Common Files\\microsoft shared\\ClickToRun\*" or module.path="c:\\program files\\Common Files\\microsoft shared\\ClickToRun\\Updates\*\*" or module.path="c:\\program files (x86)\\Common Files\\microsoft shared\\ClickToRun\\Updates\*\*" or module.path="c:\\program files\\Microsoft Office\\root\\Client\*" or module.path="c:\\program files (x86)\\Microsoft Office\\root\\Client\*" or module.path="c:\\program files\\Microsoft Office\\root\\Office*\*" or module.path="c:\\program files (x86)\\Microsoft Office\\root\\Office*\*" or module.path="c:\\program files\\Microsoft Office\\root\\vfs\\ProgramFilesCommonX64\\Microsoft Shared\\Office*\*" or module.path="c:\\program files (x86)\\Microsoft Office\\root\\vfs\\ProgramFilesCommonX64\\Microsoft Shared\\Office*\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of appvisvsubsystems64.dll
id: 3016171b-4079-48a3-9089-5b9ff8997109
status: experimental
description: Detects possible DLL hijacking of appvisvsubsystems64.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/appvisvsubsystems64.html
author: "Still Hsu"
date: 2025-10-20
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\appvisvsubsystems64.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Common Files\microsoft shared\ClickToRun\*'
            - 'c:\program files (x86)\Common Files\microsoft shared\ClickToRun\*'
            - 'c:\program files\Common Files\microsoft shared\ClickToRun\Updates\*\*'
            - 'c:\program files (x86)\Common Files\microsoft shared\ClickToRun\Updates\*\*'
            - 'c:\program files\Microsoft Office\root\Client\*'
            - 'c:\program files (x86)\Microsoft Office\root\Client\*'
            - 'c:\program files\Microsoft Office\root\Office*\*'
            - 'c:\program files (x86)\Microsoft Office\root\Office*\*'
            - 'c:\program files\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office*\*'
            - 'c:\program files (x86)\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
