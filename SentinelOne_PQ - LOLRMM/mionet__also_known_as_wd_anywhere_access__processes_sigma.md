```sql
// Translated content (automatically translated on 03-05-2025 01:26:06):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "mionet.exe" or src.process.image.path contains "mionetmanager.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential MioNet (Also known as WD Anywhere Access) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - mionet.exe
    - mionetmanager.exe
  condition: selection
id: 88102b66-9f64-425c-86cf-fb29cdd68806
status: experimental
description: Detects potential processes activity of MioNet (Also known as WD Anywhere
  Access) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of MioNet (Also known as WD Anywhere Access)
level: medium
```
