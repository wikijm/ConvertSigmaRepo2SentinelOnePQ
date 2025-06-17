```sql
// Translated content (automatically translated on 17-06-2025 01:20:42):
event.type="ModuleLoad" and (endpoint.os="windows" and (src.process.image.path="C:\Windows\System32\SystemResetPlatform\SystemResetPlatform.exe" and module.path="C:\$SysReset\Framework\Stack\RjvPlatform.dll"))
```


# Original Sigma Rule:
```yaml
title: Potential RjvPlatform.DLL Sideloading From Default Location
id: 259dda31-b7a3-444f-b7d8-17f96e8a7d0d
status: test
description: Detects loading of "RjvPlatform.dll" by the "SystemResetPlatform.exe" binary which can be abused as a method of DLL side loading since the "$SysReset" directory isn't created by default.
references:
    - https://twitter.com/0gtweet/status/1666716511988330499
author: X__Junior (Nextron Systems)
date: 2023-06-09
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image: 'C:\Windows\System32\SystemResetPlatform\SystemResetPlatform.exe'
        ImageLoaded: 'C:\$SysReset\Framework\Stack\RjvPlatform.dll'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
