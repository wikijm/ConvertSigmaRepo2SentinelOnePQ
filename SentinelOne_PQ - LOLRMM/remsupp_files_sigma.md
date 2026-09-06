```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Users\*\\AppData\\Local\\Programs\\RemSupp\\RemSupp.exe" or tgt.file.path contains "C:\\Users\*\\AppData\\Local\\Programs\\RemSupp\\Uninstall RemSupp.exe" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\RemSupp.lnk" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\RemSupp\\Local State" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\RemSupp\\Preferences" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\RemSupp\\chromium.log" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\RemSupp\\Crashpad\\metadata" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\RemSupp\\Crashpad\\settings.dat" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\RemSupp\\Local Storage\\leveldb\*" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\RemSupp\\sentry\\queue\\queue.json" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\RemSupp\\sentry\\scope_v3.json" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\RemSupp\\sentry\\session.json" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\RemSupp\\quitAndInstall.json"))
```


# Original Sigma Rule:
```yaml
title: Potential RemSupp RMM Tool File Activity
id: 0109ce68-5f04-5470-bc7f-4922773de473
status: experimental
description: |
    Detects potential files activity of RemSupp RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
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
            - 'C:\Users\*\AppData\Local\Programs\RemSupp\RemSupp.exe'
            - 'C:\Users\*\AppData\Local\Programs\RemSupp\Uninstall RemSupp.exe'
            - 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\RemSupp.lnk'
            - 'C:\Users\*\AppData\Roaming\RemSupp\Local State'
            - 'C:\Users\*\AppData\Roaming\RemSupp\Preferences'
            - 'C:\Users\*\AppData\Roaming\RemSupp\chromium.log'
            - 'C:\Users\*\AppData\Roaming\RemSupp\Crashpad\metadata'
            - 'C:\Users\*\AppData\Roaming\RemSupp\Crashpad\settings.dat'
            - 'C:\Users\*\AppData\Roaming\RemSupp\Local Storage\leveldb\*'
            - 'C:\Users\*\AppData\Roaming\RemSupp\sentry\queue\queue.json'
            - 'C:\Users\*\AppData\Roaming\RemSupp\sentry\scope_v3.json'
            - 'C:\Users\*\AppData\Roaming\RemSupp\sentry\session.json'
            - 'C:\Users\*\AppData\Roaming\RemSupp\quitAndInstall.json'
    condition: selection
falsepositives:
    - Legitimate use of RemSupp
level: medium
```
