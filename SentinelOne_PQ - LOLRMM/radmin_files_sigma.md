```sql
// Translated content (automatically translated on 31-07-2025 00:57:39):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\Windows\SysWOW64\rserver30\Radm_log.htm" or tgt.file.path contains "C:\Windows\System32\rserver30\Radm_log.htm" or tgt.file.path contains "C:\Windows\System32\rserver30\CHATLOGS\*\*.htm" or tgt.file.path contains "C:\Users\*\Documents\ChatLogs\*\*.htm"))
```


# Original Sigma Rule:
```yaml
title: Potential RAdmin RMM Tool File Activity
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith:
    - C:\Windows\SysWOW64\rserver30\Radm_log.htm
    - C:\Windows\System32\rserver30\Radm_log.htm
    - C:\Windows\System32\rserver30\CHATLOGS\*\*.htm
    - C:\Users\*\Documents\ChatLogs\*\*.htm
  condition: selection
id: a731af2c-02a3-40d0-8c86-e410c4c259cd
status: experimental
description: Detects potential files activity of RAdmin RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RAdmin
level: medium
```
