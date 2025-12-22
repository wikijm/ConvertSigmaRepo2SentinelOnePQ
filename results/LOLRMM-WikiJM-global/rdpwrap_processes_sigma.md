```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "RDPWInst.exe" or src.process.image.path contains "RDPCheck.exe" or src.process.image.path contains "RDPConf.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential rdpwrap RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - RDPWInst.exe
    - RDPCheck.exe
    - RDPConf.exe
  condition: selection
id: fc73ff2a-3bdc-4b57-bec3-8eb9e1c2c833
status: experimental
description: Detects potential processes activity of rdpwrap RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of rdpwrap
level: medium
```
