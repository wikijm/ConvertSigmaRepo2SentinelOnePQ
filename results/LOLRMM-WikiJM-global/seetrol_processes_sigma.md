```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "seetrolcenter.exe" or src.process.image.path contains "seetrolclient.exe" or src.process.image.path contains "seetrolmyservice.exe" or src.process.image.path contains "seetrolremote.exe" or src.process.image.path contains "seetrolsetting.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Seetrol RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - seetrolcenter.exe
    - seetrolclient.exe
    - seetrolmyservice.exe
    - seetrolremote.exe
    - seetrolsetting.exe
  condition: selection
id: c958ff14-82e4-43b4-9b64-e150fc85144c
status: experimental
description: Detects potential processes activity of Seetrol RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Seetrol
level: medium
```
