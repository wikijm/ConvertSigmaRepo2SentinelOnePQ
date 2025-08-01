```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\clfs.sys" and ((src.process.image.path contains ":\Perflogs\" or src.process.image.path contains ":\Users\Public\" or src.process.image.path contains "\Temporary Internet" or src.process.image.path contains "\Windows\Temp\") or ((src.process.image.path contains ":\Users\" and src.process.image.path contains "\Favorites\") or (src.process.image.path contains ":\Users\" and src.process.image.path contains "\Favourites\") or (src.process.image.path contains ":\Users\" and src.process.image.path contains "\Contacts\") or (src.process.image.path contains ":\Users\" and src.process.image.path contains "\Pictures\")))))
```


# Original Sigma Rule:
```yaml
title: Clfs.SYS Loaded By Process Located In a Potential Suspicious Location
id: fb4e2211-6d08-426b-8e6f-0d4a161e3b1d
status: experimental
description: Detects Clfs.sys being loaded by a process running from a potentially suspicious location. Clfs.sys is loaded as part of many CVEs exploits that targets Common Log File.
references:
    - https://ssd-disclosure.com/ssd-advisory-common-log-file-system-clfs-driver-pe/
    - https://x.com/Threatlabz/status/1879956781360976155
author: X__Junior
date: 2025-01-20
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: image_load
    product: windows
detection:
    selection_dll:
        ImageLoaded|endswith: '\clfs.sys'
    selection_folders_1:
        Image|contains:
            - ':\Perflogs\'
            - ':\Users\Public\'
            - '\Temporary Internet'
            - '\Windows\Temp\'
    selection_folders_2:
        - Image|contains|all:
              - ':\Users\'
              - '\Favorites\'
        - Image|contains|all:
              - ':\Users\'
              - '\Favourites\'
        - Image|contains|all:
              - ':\Users\'
              - '\Contacts\'
        - Image|contains|all:
              - ':\Users\'
              - '\Pictures\'
    condition: selection_dll and 1 of selection_folders_*
falsepositives:
    - Unknown
level: medium
```
