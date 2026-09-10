```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files (x86)\\HopToDesk\\HopToDesk.exe" or tgt.file.path contains "C:\\Program Files (x86)\\HopToDesk\\privacyhelper.exe" or tgt.file.path contains "C:\\Program Files (x86)\\HopToDesk\\PrivacyMode.dll" or tgt.file.path contains "C:\\Program Files (x86)\\HopToDesk\\sciter.dll" or tgt.file.path contains "C:\\Users\*\\AppData\\Local\\Temp\\sciter.dll" or tgt.file.path contains "C:\\Users\*\\AppData\\Local\\Temp\\privacyhelper.exe" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\HopToDesk\\config\*" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\HopToDesk\\config\\hoptodesk.toml" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\HopToDesk\\config\\HopToDesk_rCURRENT.log" or tgt.file.path="*/System/Volumes/Data/Users/*/Library/Logs/HopToDesk/hoptodesk_rCURRENT.log"))
```


# Original Sigma Rule:
```yaml
title: Potential HopToDesk RMM Tool File Activity
id: f396f6d4-3cd9-4419-bc8f-01bfe3784c12
status: experimental
description: |
    Detects potential files activity of HopToDesk RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\Program Files (x86)\HopToDesk\HopToDesk.exe'
            - 'C:\Program Files (x86)\HopToDesk\privacyhelper.exe'
            - 'C:\Program Files (x86)\HopToDesk\PrivacyMode.dll'
            - 'C:\Program Files (x86)\HopToDesk\sciter.dll'
            - 'C:\Users\*\AppData\Local\Temp\sciter.dll'
            - 'C:\Users\*\AppData\Local\Temp\privacyhelper.exe'
            - 'C:\Users\*\AppData\Roaming\HopToDesk\config\*'
            - 'C:\Users\*\AppData\Roaming\HopToDesk\config\hoptodesk.toml'
            - 'C:\Users\*\AppData\Roaming\HopToDesk\config\HopToDesk_rCURRENT.log'
            - '/System/Volumes/Data/Users/*/Library/Logs/HopToDesk/hoptodesk_rCURRENT.log'
    condition: selection
falsepositives:
    - Legitimate use of HopToDesk
level: medium
```
