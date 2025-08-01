```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and ((module.path contains "\hdwwiz.cpl" or module.path contains "\appwiz.cpl") and (not (module.path contains ":\Windows\System32\" or module.path contains ":\Windows\SysWOW64\" or module.path contains ":\Windows\WinSxS\"))))
```


# Original Sigma Rule:
```yaml
title: System Control Panel Item Loaded From Uncommon Location
id: 2b140a5c-dc02-4bb8-b6b1-8bdb45714cde
status: test
description: Detects image load events of system control panel items (.cpl) from uncommon or non-system locations which might be the result of sideloading.
references:
    - https://www.hexacorn.com/blog/2024/01/06/1-little-known-secret-of-fondue-exe/
    - https://www.hexacorn.com/blog/2024/01/01/1-little-known-secret-of-hdwwiz-exe/
author: Anish Bogati
date: 2024-01-09
tags:
    - attack.defense-evasion
    - attack.t1036
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded|endswith:
            - '\hdwwiz.cpl' # Usually loaded by hdwwiz.exe
            - '\appwiz.cpl' # Usually loaded by fondue.exe
    filter_main_legit_location:
        ImageLoaded|contains:
            - ':\Windows\System32\'
            - ':\Windows\SysWOW64\'
            - ':\Windows\WinSxS\'
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: medium
```
