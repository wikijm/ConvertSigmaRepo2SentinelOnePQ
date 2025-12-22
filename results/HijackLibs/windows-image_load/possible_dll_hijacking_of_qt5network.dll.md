```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\qt5network.dll" and (not (module.path in ("c:\\program files\\LSoft Technologies\\Active@ Data Studio\*","c:\\program files (x86)\\LSoft Technologies\\Active@ Data Studio\*","c:\\program files\\LSoft Technologies\\Active@ File Recovery\*","c:\\program files (x86)\\LSoft Technologies\\Active@ File Recovery\*","c:\\program files\\LSoft Technologies\\Active@ Disk Editor\*","c:\\program files (x86)\\LSoft Technologies\\Active@ Disk Editor\*","c:\\program files\\LSoft Technologies\\Active@ Password Changer\*","c:\\program files (x86)\\LSoft Technologies\\Active@ Password Changer\*","c:\\program files\\LSoft Technologies\\Active@ ISO Manager\*","c:\\program files (x86)\\LSoft Technologies\\Active@ ISO Manager\*","c:\\program files\\LSoft Technologies\\Active@ UNERASER\*","c:\\program files (x86)\\LSoft Technologies\\Active@ UNERASER\*","c:\\program files\\LSoft Technologies\\Active@ KillDisk 25\*","c:\\program files (x86)\\LSoft Technologies\\Active@ KillDisk 25\*","c:\\program files\\LSoft Technologies\\Active@ UNDELETE\*","c:\\program files (x86)\\LSoft Technologies\\Active@ UNDELETE\*","c:\\program files\\LSoft Technologies\\Active@ Disk Monitor\*","c:\\program files (x86)\\LSoft Technologies\\Active@ Disk Monitor\*","c:\\program files\\LSoft Technologies\\Active@ Partition Manager\*","c:\\program files (x86)\\LSoft Technologies\\Active@ Partition Manager\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of qt5network.dll
id: 9190191b-7904-48a3-3158-5b9ff8134247
status: experimental
description: Detects possible DLL hijacking of qt5network.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/qt/qt5network.html
author: "Jai Minton"
date: 2025-05-09
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\qt5network.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\LSoft Technologies\Active@ Data Studio\*'
            - 'c:\program files (x86)\LSoft Technologies\Active@ Data Studio\*'
            - 'c:\program files\LSoft Technologies\Active@ File Recovery\*'
            - 'c:\program files (x86)\LSoft Technologies\Active@ File Recovery\*'
            - 'c:\program files\LSoft Technologies\Active@ Disk Editor\*'
            - 'c:\program files (x86)\LSoft Technologies\Active@ Disk Editor\*'
            - 'c:\program files\LSoft Technologies\Active@ Password Changer\*'
            - 'c:\program files (x86)\LSoft Technologies\Active@ Password Changer\*'
            - 'c:\program files\LSoft Technologies\Active@ ISO Manager\*'
            - 'c:\program files (x86)\LSoft Technologies\Active@ ISO Manager\*'
            - 'c:\program files\LSoft Technologies\Active@ UNERASER\*'
            - 'c:\program files (x86)\LSoft Technologies\Active@ UNERASER\*'
            - 'c:\program files\LSoft Technologies\Active@ KillDisk 25\*'
            - 'c:\program files (x86)\LSoft Technologies\Active@ KillDisk 25\*'
            - 'c:\program files\LSoft Technologies\Active@ UNDELETE\*'
            - 'c:\program files (x86)\LSoft Technologies\Active@ UNDELETE\*'
            - 'c:\program files\LSoft Technologies\Active@ Disk Monitor\*'
            - 'c:\program files (x86)\LSoft Technologies\Active@ Disk Monitor\*'
            - 'c:\program files\LSoft Technologies\Active@ Partition Manager\*'
            - 'c:\program files (x86)\LSoft Technologies\Active@ Partition Manager\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
