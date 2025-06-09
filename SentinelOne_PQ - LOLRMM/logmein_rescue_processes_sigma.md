```sql
// Translated content (automatically translated on 09-06-2025 00:56:01):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*support-logmeinrescue*.exe" or src.process.image.path contains "support-logmeinrescue.exe" or src.process.image.path contains "lmi_rescue.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential LogMeIn rescue RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - support-logmeinrescue*.exe
    - support-logmeinrescue.exe
    - lmi_rescue.exe
  condition: selection
id: 1d9b0eb0-ad3f-4385-bd87-8a63c8c946d8
status: experimental
description: Detects potential processes activity of LogMeIn rescue RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of LogMeIn rescue
level: medium
```
