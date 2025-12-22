```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\mRemoteNG\\mRemoteNG.log" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\mRemoteNG\\confCons.xml" or tgt.file.path="*C:\\Users\*\\AppData\*\\mRemoteNG\**10\\user.config"))
```


# Original Sigma Rule:
```yaml
title: Potential mRemoteNG RMM Tool File Activity
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
id: f05be463-6a61-4a89-ab8b-f17bf9b879e3
status: experimental
description: Detects potential files activity of mRemoteNG RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of mRemoteNG
level: medium
```
