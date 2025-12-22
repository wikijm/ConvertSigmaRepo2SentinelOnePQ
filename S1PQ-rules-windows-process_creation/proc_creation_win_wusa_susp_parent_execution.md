```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\wusa.exe" and ((src.process.image.path contains ":\\Perflogs\\" or src.process.image.path contains ":\\Users\\Public\\" or src.process.image.path contains ":\\Windows\\Temp\\" or src.process.image.path contains "\\Appdata\\Local\\Temp\\" or src.process.image.path contains "\\Temporary Internet") or ((src.process.image.path contains ":\\Users\\" and src.process.image.path contains "\\Favorites\\") or (src.process.image.path contains ":\\Users\\" and src.process.image.path contains "\\Favourites\\") or (src.process.image.path contains ":\\Users\\" and src.process.image.path contains "\\Contacts\\") or (src.process.image.path contains ":\\Users\\" and src.process.image.path contains "\\Pictures\\"))) and (not tgt.process.cmdline contains ".msu")))
```


# Original Sigma Rule:
```yaml
title: Wusa.EXE Executed By Parent Process Located In Suspicious Location
id: ef64fc9c-a45e-43cc-8fd8-7d75d73b4c99
status: test
description: |
    Detects execution of the "wusa.exe" (Windows Update Standalone Installer) utility by a parent process that is located in a suspicious location.
    Attackers could instantiate an instance of "wusa.exe" in order to bypass User Account Control (UAC). They can duplicate the access token from "wusa.exe" to gain elevated privileges.
references:
    - https://www.fortinet.com/blog/threat-research/konni-campaign-distributed-via-malicious-document
author: X__Junior (Nextron Systems)
date: 2023-11-26
modified: 2024-08-15
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\wusa.exe'
    selection_paths_1:
        ParentImage|contains:
            # Note: Add additional suspicious locations to increase coverage
            - ':\Perflogs\'
            - ':\Users\Public\'
            - ':\Windows\Temp\'
            - '\Appdata\Local\Temp\'
            - '\Temporary Internet'
    selection_paths_2:
        - ParentImage|contains|all:
              - ':\Users\'
              - '\Favorites\'
        - ParentImage|contains|all:
              - ':\Users\'
              - '\Favourites\'
        - ParentImage|contains|all:
              - ':\Users\'
              - '\Contacts\'
        - ParentImage|contains|all:
              - ':\Users\'
              - '\Pictures\'
    filter_main_msu:
        # Note: We exclude MSU extension files. A better approach is to baseline installation of updates in your env to avoid false negatives.
        CommandLine|contains: '.msu'
    condition: selection_img and 1 of selection_paths_* and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
