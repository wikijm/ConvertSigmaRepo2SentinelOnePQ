```sql
// Translated content (automatically translated on 17-07-2025 00:56:45):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\Windows\Action1\action1_agent.exe" or tgt.file.path contains "C:\Windows\Action1\*" or tgt.file.path contains "C:\Windows\Action1\scripts\*" or tgt.file.path contains "C:\Windows\Action1\rule_data\*" or tgt.file.path="*C:\Windows\Action1\action1_log_*.log"))
```


# Original Sigma Rule:
```yaml
title: Potential Action1 RMM Tool File Activity
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith:
    - C:\Windows\Action1\action1_agent.exe
    - C:\Windows\Action1\*
    - C:\Windows\Action1\scripts\*
    - C:\Windows\Action1\rule_data\*
    - C:\Windows\Action1\action1_log_*.log
  condition: selection
id: 9a267345-afb8-48be-b718-575be9603f4c
status: experimental
description: Detects potential files activity of Action1 RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Action1
level: medium
```
