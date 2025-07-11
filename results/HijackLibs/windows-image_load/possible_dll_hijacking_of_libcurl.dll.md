```sql
// Translated content (automatically translated on 11-07-2025 01:53:39):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\libcurl.dll" and (not (module.path="c:\program files\Notepad++\updater\*" or module.path="c:\program files (x86)\Notepad++\updater\*" or module.path="c:\program files\WindowsApps\MSTeams_*\*" or module.path="c:\program files (x86)\WindowsApps\MSTeams_*\*" or module.path="c:\program files\Coolmuster\Coolmuster PDF Creator Pro\*\Bin\*" or module.path="c:\program files (x86)\Coolmuster\Coolmuster PDF Creator Pro\*\Bin\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of libcurl.dll
id: 5734981b-6363-48a3-2268-5b9ff8671828
status: experimental
description: Detects possible DLL hijacking of libcurl.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/curl/libcurl.html
author: "Still Hsu"
date: 2024-05-26
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\libcurl.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Notepad++\updater\*'
            - 'c:\program files (x86)\Notepad++\updater\*'
            - 'c:\program files\WindowsApps\MSTeams_*\*'
            - 'c:\program files (x86)\WindowsApps\MSTeams_*\*'
            - 'c:\program files\Coolmuster\Coolmuster PDF Creator Pro\*\Bin\*'
            - 'c:\program files (x86)\Coolmuster\Coolmuster PDF Creator Pro\*\Bin\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
