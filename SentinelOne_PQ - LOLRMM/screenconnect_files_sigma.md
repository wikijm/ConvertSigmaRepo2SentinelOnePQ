```sql
// Translated content (automatically translated on 08-10-2024 15:38:03):
event.category="file" and (endpoint.os="windows" and (tgt.file.path="*C:\Program Files*\ScreenConnect\App_Data\Session.db" or tgt.file.path="*C:\Program Files*\ScreenConnect\App_Data\User.xml" or tgt.file.path="*C:\ProgramData\ScreenConnect Client*\user.config"))
```


# Original Sigma Rule:
```yaml
title: Potential ScreenConnect RMM Tool File Activity
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith:
    - C:\Program Files*\ScreenConnect\App_Data\Session.db
    - C:\Program Files*\ScreenConnect\App_Data\User.xml
    - C:\ProgramData\ScreenConnect Client*\user.config
  condition: selection
id: adb2440e-8700-4ab3-9a1a-6b761826955f
status: experimental
description: Detects potential files activity of ScreenConnect RMM tool
author: LOLRMM Project
date: 2024-08-07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ScreenConnect
level: medium
```