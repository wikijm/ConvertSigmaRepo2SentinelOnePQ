```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and ((module.path contains "\\coreclr.dll" or module.path contains "\\facesdk.dll" or module.path contains "\\HPCustPartUI.dll" or module.path contains "\\libcef.dll" or module.path contains "\\ZIPDLL.dll") and ((module.path contains ":\\Perflogs\\" or module.path contains ":\\Users\\Public\\" or module.path contains "\\Temporary Internet" or module.path contains "\\Windows\\Temp\\") or ((module.path contains ":\\Users\\" and module.path contains "\\Favorites\\") or (module.path contains ":\\Users\\" and module.path contains "\\Favourites\\") or (module.path contains ":\\Users\\" and module.path contains "\\Contacts\\") or (module.path contains ":\\Users\\" and module.path contains "\\Pictures\\")))))
```


# Original Sigma Rule:
```yaml
title: Abusable DLL Potential Sideloading From Suspicious Location
id: 799a5f48-0ac1-4e0f-9152-71d137d48c2a
status: test
description: Detects potential DLL sideloading of DLLs that are known to be abused from suspicious locations
references:
    - https://www.trendmicro.com/en_us/research/23/f/behind-the-scenes-unveiling-the-hidden-workings-of-earth-preta.html
    - https://research.checkpoint.com/2023/beyond-the-horizon-traveling-the-world-on-camaro-dragons-usb-flash-drives/
author: X__Junior (Nextron Systems)
date: 2023-07-11
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: image_load
    product: windows
detection:
    selection_dll:
        ImageLoaded|endswith:
            # Note: Add more generic DLLs that cannot be pin-pointed to a single application
            - '\coreclr.dll'
            - '\facesdk.dll'
            - '\HPCustPartUI.dll'
            - '\libcef.dll'
            - '\ZIPDLL.dll'
    selection_folders_1:
        ImageLoaded|contains:
            - ':\Perflogs\'
            - ':\Users\Public\'
            - '\Temporary Internet'
            - '\Windows\Temp\'
    selection_folders_2:
        - ImageLoaded|contains|all:
              - ':\Users\'
              - '\Favorites\'
        - ImageLoaded|contains|all:
              - ':\Users\'
              - '\Favourites\'
        - ImageLoaded|contains|all:
              - ':\Users\'
              - '\Contacts\'
        - ImageLoaded|contains|all:
              - ':\Users\'
              - '\Pictures\'
    condition: selection_dll and 1 of selection_folders_*
falsepositives:
    - Unknown
level: high
```
