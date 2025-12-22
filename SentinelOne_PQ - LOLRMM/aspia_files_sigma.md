```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\aspia\\client.ini" or tgt.file.path="*C:\\Users\*\\AppData\\Local\\Temp\\aspia\\aspia_client-*.log" or tgt.file.path contains "C:\\Program Files\\Aspia\\Client\\qt.conf"))
```


# Original Sigma Rule:
```yaml
title: Potential Aspia RMM Tool File Activity
id: 043a2b6b-dc86-43ae-91f1-157c2b6efddb
status: experimental
description: |
    Detects potential files activity of Aspia RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - C:\Users\*\AppData\Roaming\aspia\client.ini
            - C:\Users\*\AppData\Local\Temp\aspia\aspia_client-*.log
            - C:\Program Files\Aspia\Client\qt.conf
    condition: selection
falsepositives:
    - Legitimate use of Aspia
level: medium
```
