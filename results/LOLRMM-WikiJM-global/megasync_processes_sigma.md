```sql
// Translated content (automatically translated on 07-09-2025 01:36:04):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\MEGAsyncSetup64.exe" or src.process.image.path contains "\\MEGAupdater.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential MEGAsync RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\MEGAsyncSetup64.exe'
    - '*\MEGAupdater.exe'
  condition: selection
id: a0026069-13de-49ef-be27-1951aecc3581
status: experimental
description: Detects potential processes activity of MEGAsync RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of MEGAsync
level: medium
```
