```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "mionet.exe" or src.process.image.path contains "mionetmanager.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential MioNet (WD Anywhere Access) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - mionet.exe
    - mionetmanager.exe
  condition: selection
id: a7966542-dfb9-4d1d-b984-4444f5a76bf8
status: experimental
description: Detects potential processes activity of MioNet (WD Anywhere Access) RMM
  tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of MioNet (WD Anywhere Access)
level: medium
```
