```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and ((src.process.image.path contains "\VMwareXferlogs.exe" and module.path contains "\glib-2.0.dll") and (not module.path contains "C:\Program Files\VMware\")))
```


# Original Sigma Rule:
```yaml
title: Potential DLL Sideloading Via VMware Xfer
id: 9313dc13-d04c-46d8-af4a-a930cc55d93b
status: test
description: Detects loading of a DLL by the VMware Xfer utility from the non-default directory which may be an attempt to sideload arbitrary DLL
references:
    - https://www.sentinelone.com/labs/lockbit-ransomware-side-loads-cobalt-strike-beacon-with-legitimate-vmware-utility/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-02
modified: 2023-02-17
tags:
    - attack.defense-evasion
    - attack.t1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        Image|endswith: '\VMwareXferlogs.exe'
        ImageLoaded|endswith: '\glib-2.0.dll'
    filter: # VMware might be installed in another path so update the rule accordingly
        ImageLoaded|startswith: 'C:\Program Files\VMware\'
    condition: selection and not filter
falsepositives:
    - Unlikely
level: high
```
