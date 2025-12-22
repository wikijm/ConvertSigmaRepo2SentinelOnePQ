```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "tvnviewer.exe" or src.process.image.path="*TightVNCViewerPortable*.exe" or src.process.image.path contains "tvnserver.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential TightVNC RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - tvnviewer.exe
    - TightVNCViewerPortable*.exe
    - tvnserver.exe
  condition: selection
id: 0ec0cc81-6194-47b2-82bc-ae497dec7baa
status: experimental
description: Detects potential processes activity of TightVNC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of TightVNC
level: medium
```
