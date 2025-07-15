```sql
// Translated content (automatically translated on 15-07-2025 00:57:10):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "mwcliun.exe" or src.process.image.path contains "pcnmgr.exe" or src.process.image.path contains "webexpcnow.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Pcnow RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - mwcliun.exe
    - pcnmgr.exe
    - webexpcnow.exe
  condition: selection
id: 2bc661c4-b05f-4971-bfc8-eef0bcddad00
status: experimental
description: Detects potential processes activity of Pcnow RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Pcnow
level: medium
```
