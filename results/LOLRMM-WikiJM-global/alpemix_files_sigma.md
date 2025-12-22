```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.category="file" and (endpoint.os="windows" and tgt.file.path contains "%localappdata%\\Alpemix\\Alpemix.ini")
```


# Original Sigma Rule:
```yaml
title: Potential Alpemix RMM Tool File Activity
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith:
    - '%localappdata%\Alpemix\Alpemix.ini'
  condition: selection
id: 6737b828-5c7c-4341-b016-0f6b56c24dd5
status: experimental
description: Detects potential files activity of Alpemix RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Alpemix
level: medium
```
