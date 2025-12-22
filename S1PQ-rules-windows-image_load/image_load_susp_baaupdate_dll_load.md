```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and (src.process.image.path contains "\\BaaUpdate.exe" and module.path contains ".dll" and (module.path contains ":\\Perflogs\\" or module.path contains ":\\Users\\Default\\" or module.path contains ":\\Users\\Public\\" or module.path contains ":\\Windows\\Temp\\" or module.path contains "\\AppData\\Local\\Temp\\" or module.path contains "\\AppData\\Roaming\\" or module.path contains "\\Contacts\\" or module.path contains "\\Favorites\\" or module.path contains "\\Favourites\\" or module.path contains "\\Links\\" or module.path contains "\\Music\\" or module.path contains "\\Pictures\\" or module.path contains "\\ProgramData\\" or module.path contains "\\Temporary Internet" or module.path contains "\\Videos\\")))
```


# Original Sigma Rule:
```yaml
title: BaaUpdate.exe Suspicious DLL Load
id: 6e8fe0a8-ba0b-4a93-8f9e-82657e7a5984
related:
    - id: 9f38c1db-e2ae-40bf-81d0-5b68f73fb512 # Suspicious BitLocker Access Agent Update Utility Execution
      type: similar
status: experimental
description: |
    Detects BitLocker Access Agent Update Utility (baaupdate.exe) loading DLLs from suspicious locations that are publicly writable which could indicate an attempt to lateral movement via BitLocker DCOM & COM Hijacking.
    This technique abuses COM Classes configured as INTERACTIVE USER to spawn processes in the context of the logged-on user's session. Specifically, it targets the BDEUILauncher Class (CLSID ab93b6f1-be76-4185-a488-a9001b105b94)
    which can launch BaaUpdate.exe, which is vulnerable to COM Hijacking when started with input parameters. This allows attackers to execute code in the user's context without needing to steal credentials or use additional techniques to compromise the account.
references:
    - https://github.com/rtecCyberSec/BitlockMove
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-10-18
tags:
    - attack.defense-evasion
    - attack.t1218
    - attack.lateral-movement
    - attack.t1021.003
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\BaaUpdate.exe'
        ImageLoaded|endswith: '.dll'
        ImageLoaded|contains:
            - ':\Perflogs\'
            - ':\Users\Default\'
            - ':\Users\Public\'
            - ':\Windows\Temp\'
            - '\AppData\Local\Temp\'
            - '\AppData\Roaming\'
            - '\Contacts\'
            - '\Favorites\'
            - '\Favourites\'
            - '\Links\'
            - '\Music\'
            - '\Pictures\'
            - '\ProgramData\'
            - '\Temporary Internet'
            - '\Videos\'
    condition: selection
falsepositives:
    - Unknown
level: high
```
