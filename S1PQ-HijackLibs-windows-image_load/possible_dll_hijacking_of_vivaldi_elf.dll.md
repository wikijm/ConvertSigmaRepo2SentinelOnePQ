```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\vivaldi_elf.dll" and (not (module.path in ("c:\users\*\appdata\local\Vivaldi\Application\*","c:\users\*\appdata\local\Vivaldi\Application\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of vivaldi_elf.dll
id: 5086081b-2523-48a3-4236-5b9ff8819409
status: experimental
description: Detects possible DLL hijacking of vivaldi_elf.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/vivaldi/vivaldi_elf.html
author: "Wietze Beukema"
date: 2023-04-22
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\vivaldi_elf.dll'
    filter:
        ImageLoaded:
            - 'c:\users\*\appdata\local\Vivaldi\Application\*'
            - 'c:\users\*\appdata\local\Vivaldi\Application\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
