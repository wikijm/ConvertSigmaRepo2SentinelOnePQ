```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and ((module.path contains "\\SmadHook32c.dll" or module.path contains "\\SmadHook64c.dll") and (not ((src.process.image.path in ("C:\\Program Files (x86)\\SMADAV\\SmadavProtect32.exe","C:\\Program Files (x86)\\SMADAV\\SmadavProtect64.exe","C:\\Program Files\\SMADAV\\SmadavProtect32.exe","C:\\Program Files\\SMADAV\\SmadavProtect64.exe")) and (module.path contains "C:\\Program Files (x86)\\SMADAV\\" or module.path contains "C:\\Program Files\\SMADAV\\")))))
```


# Original Sigma Rule:
```yaml
title: Potential SmadHook.DLL Sideloading
id: 24b6cf51-6122-469e-861a-22974e9c1e5b
status: test
description: Detects potential DLL sideloading of "SmadHook.dll", a DLL used by SmadAV antivirus
references:
    - https://research.checkpoint.com/2023/malware-spotlight-camaro-dragons-tinynote-backdoor/
    - https://www.qurium.org/alerts/targeted-malware-against-crph/
author: X__Junior (Nextron Systems)
date: 2023-06-01
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith:
            - '\SmadHook32c.dll'
            - '\SmadHook64c.dll'
    filter_main_legit_path:
        Image:
            - 'C:\Program Files (x86)\SMADAV\SmadavProtect32.exe'
            - 'C:\Program Files (x86)\SMADAV\SmadavProtect64.exe'
            - 'C:\Program Files\SMADAV\SmadavProtect32.exe'
            - 'C:\Program Files\SMADAV\SmadavProtect64.exe'
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\SMADAV\'
            - 'C:\Program Files\SMADAV\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high
```
