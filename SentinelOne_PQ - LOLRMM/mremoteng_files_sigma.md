```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\mRemoteNG\\mRemoteNG.log" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\mRemoteNG\\confCons.xml" or tgt.file.path="*C:\\Users\*\\AppData\*\\mRemoteNG\**10\\user.config"))
```


# Original Sigma Rule:
```yaml
title: Potential mRemoteNG RMM Tool File Activity
id: 453adbd6-da18-4d1f-b7f6-ef5cdbc43684
status: experimental
description: |
    Detects potential files activity of mRemoteNG RMM tool
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
            - C:\Users\*\AppData\Roaming\mRemoteNG\mRemoteNG.log
            - C:\Users\*\AppData\Roaming\mRemoteNG\confCons.xml
            - C:\Users\*\AppData\*\mRemoteNG\**10\user.config
    condition: selection
falsepositives:
    - Legitimate use of mRemoteNG
level: medium
```
