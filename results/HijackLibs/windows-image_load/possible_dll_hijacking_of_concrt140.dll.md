```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\concrt140.dll" and (not (module.path="c:\\program files\\Microsoft Visual Studio\*\\Community\\Common7\\IDE\\VC\\vcpackages\*" or module.path="c:\\program files (x86)\\Microsoft Visual Studio\*\\Community\\Common7\\IDE\\VC\\vcpackages\*" or module.path="c:\\program files\\Microsoft Visual Studio\*\\BuildTools\\Common7\\IDE\\VC\\vcpackages\*" or module.path="c:\\program files (x86)\\Microsoft Visual Studio\*\\BuildTools\\Common7\\IDE\\VC\\vcpackages\*" or module.path="c:\\program files\\Microsoft Visual Studio\*\\BuildTools\\Common7\\IDE\*" or module.path="c:\\program files (x86)\\Microsoft Visual Studio\*\\BuildTools\\Common7\\IDE\*" or module.path="c:\\program files\\Microsoft Intune Management Extension\*" or module.path="c:\\program files (x86)\\Microsoft Intune Management Extension\*" or module.path="c:\\program files\\Microsoft\\Edge\\Application\*\*" or module.path="c:\\program files (x86)\\Microsoft\\Edge\\Application\*\*" or module.path="c:\\program files\\Microsoft\\EdgeWebView\\Application\*\*" or module.path="c:\\program files (x86)\\Microsoft\\EdgeWebView\\Application\*\*" or module.path="c:\\program files\\microsoft\\edgewebview\\application\*\*" or module.path="c:\\program files (x86)\\microsoft\\edgewebview\\application\*\*" or module.path="c:\\program files\\Microsoft RDInfra\\RDMonitoringAgent_*\\Agent\*" or module.path="c:\\program files (x86)\\Microsoft RDInfra\\RDMonitoringAgent_*\\Agent\*" or module.path="c:\\program files\\WindowsApps\\Microsoft.VCLibs.*\*" or module.path="c:\\program files (x86)\\WindowsApps\\Microsoft.VCLibs.*\*" or module.path="c:\\program files\\WindowsApps\\Microsoft.OutlookForWindows_*\*" or module.path="c:\\program files (x86)\\WindowsApps\\Microsoft.OutlookForWindows_*\*" or module.path="c:\\windows\\system32\*" or module.path="c:\\windows\\syswow64\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of concrt140.dll
id: 8484041b-9387-48a3-7560-5b9ff8877196
status: experimental
description: Detects possible DLL hijacking of concrt140.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/concrt140.html
author: "Austin Worline"
date: 2025-04-06
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\concrt140.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Microsoft Visual Studio\*\Community\Common7\IDE\VC\vcpackages\*'
            - 'c:\program files (x86)\Microsoft Visual Studio\*\Community\Common7\IDE\VC\vcpackages\*'
            - 'c:\program files\Microsoft Visual Studio\*\BuildTools\Common7\IDE\VC\vcpackages\*'
            - 'c:\program files (x86)\Microsoft Visual Studio\*\BuildTools\Common7\IDE\VC\vcpackages\*'
            - 'c:\program files\Microsoft Visual Studio\*\BuildTools\Common7\IDE\*'
            - 'c:\program files (x86)\Microsoft Visual Studio\*\BuildTools\Common7\IDE\*'
            - 'c:\program files\Microsoft Intune Management Extension\*'
            - 'c:\program files (x86)\Microsoft Intune Management Extension\*'
            - 'c:\program files\Microsoft\Edge\Application\*\*'
            - 'c:\program files (x86)\Microsoft\Edge\Application\*\*'
            - 'c:\program files\Microsoft\EdgeWebView\Application\*\*'
            - 'c:\program files (x86)\Microsoft\EdgeWebView\Application\*\*'
            - 'c:\program files\microsoft\edgewebview\application\*\*'
            - 'c:\program files (x86)\microsoft\edgewebview\application\*\*'
            - 'c:\program files\Microsoft RDInfra\RDMonitoringAgent_*\Agent\*'
            - 'c:\program files (x86)\Microsoft RDInfra\RDMonitoringAgent_*\Agent\*'
            - 'c:\program files\WindowsApps\Microsoft.VCLibs.*\*'
            - 'c:\program files (x86)\WindowsApps\Microsoft.VCLibs.*\*'
            - 'c:\program files\WindowsApps\Microsoft.OutlookForWindows_*\*'
            - 'c:\program files (x86)\WindowsApps\Microsoft.OutlookForWindows_*\*'
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
