```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.category="file" and (endpoint.os="windows" and tgt.file.path contains "%AppData%\\GoTo\\Logs\\goto.log")
```


# Original Sigma Rule:
```yaml
title: Potential GoToMyPC RMM Tool File Activity
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith:
    - '%AppData%\GoTo\Logs\goto.log'
  condition: selection
id: 987976ac-6971-4332-894a-916a4a631629
status: experimental
description: Detects potential files activity of GoToMyPC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of GoToMyPC
level: medium
```
